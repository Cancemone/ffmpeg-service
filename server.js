require("dotenv").config();
const express = require("express");
const { execFile } = require("child_process");
const { promisify } = require("util");
const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const dns = require("dns").promises;
const net = require("net");
const {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
} = require("@aws-sdk/client-s3");

const execRaw = promisify(execFile);

// Hard per-invocation timeouts on child processes. Without these a single
// wedged ffmpeg/ffprobe would hold CPU/RAM on the VPS indefinitely, long
// after the Vercel caller has already timed out. killSignal: "SIGKILL"
// because ffmpeg ignores SIGTERM in some codepaths.
const FFPROBE_TIMEOUT_MS = 15_000;
const FFMPEG_TIMEOUT_MS = 300_000; // 5 min — covers worst-case 30-clip merge

async function exec(cmd, args, opts = {}) {
  const defaultTimeout =
    cmd === "ffprobe" ? FFPROBE_TIMEOUT_MS : FFMPEG_TIMEOUT_MS;
  try {
    return await execRaw(cmd, args, {
      timeout: defaultTimeout,
      killSignal: "SIGKILL",
      maxBuffer: 16 * 1024 * 1024,
      ...opts,
    });
  } catch (err) {
    // execFile's default Error.message is the command line, which truncates
    // the actual ffmpeg/ffprobe diagnostic. Surface the tail of stderr so the
    // caller sees why the filtergraph / codec / input failed.
    const stderr = (err.stderr || "").toString();
    const tail = stderr.slice(-1500).trim();
    if (tail) err.message = `${cmd} failed: ${tail}`;
    throw err;
  }
}

const app = express();
// 64kb cap: biggest legitimate payload is /merge with up to 30 clip URLs plus
// /burn-subs with a pre-transcribed word list. Both fit comfortably under this.
app.use(express.json({ limit: "64kb" }));

const AUTH_TOKEN = process.env.AUTH_TOKEN;
if (!AUTH_TOKEN) {
  console.error("FATAL: AUTH_TOKEN env var is required. Refusing to start.");
  process.exit(1);
}

// --- R2 helpers ---

function getR2() {
  return new S3Client({
    region: "auto",
    endpoint: process.env.R2_ENDPOINT,
    credentials: {
      accessKeyId: process.env.R2_ACCESS_KEY_ID,
      secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
    },
  });
}

const BUCKET = process.env.R2_BUCKET || "ugc-video";
const R2_PUBLIC_URL = process.env.R2_PUBLIC_URL;

function tmpPath(ext) {
  return path.join(os.tmpdir(), `ff_${crypto.randomBytes(6).toString("hex")}${ext}`);
}

// --- SSRF protection ---
//
// `download()` fetches attacker-influenced URLs (creative video URLs, music
// URLs, thumbnail sources). Without validation, a caller can point us at
// cloud metadata (169.254.169.254), localhost services, or LAN hosts — the
// body would then be uploaded to R2, making this an exfiltration channel.
//
// Defense:
//   1. Scheme must be https (or http only if explicitly opted in via
//      ALLOW_HTTP_DOWNLOADS=true for local dev).
//   2. Optional hostname allowlist via ALLOWED_DOWNLOAD_HOSTS (comma-separated
//      exact hosts or "*.suffix" patterns). If unset, any public hostname is
//      accepted — the private-IP block below remains the safety net.
//   3. DNS-resolve the hostname and reject loopback/private/link-local ranges
//      for every resolved address.
//   4. Redirects are handled manually so each hop is re-validated.

const ALLOW_HTTP_DOWNLOADS = process.env.ALLOW_HTTP_DOWNLOADS === "true";
const ALLOWED_DOWNLOAD_HOSTS = (process.env.ALLOWED_DOWNLOAD_HOSTS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

function isPrivateIp(addr) {
  const family = net.isIP(addr);
  if (family === 0) return true; // not a valid IP — treat as unsafe
  if (family === 4) {
    const parts = addr.split(".").map((n) => parseInt(n, 10));
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local incl. cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast + reserved
    return false;
  }
  // IPv6
  const lower = addr.toLowerCase();
  if (lower === "::1" || lower === "::") return true;
  if (lower.startsWith("fe80:") || lower.startsWith("fe90:")) return true; // link-local
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // ULA fc00::/7
  if (lower.startsWith("::ffff:")) {
    // IPv4-mapped — re-check the embedded v4 address
    const v4 = lower.slice("::ffff:".length);
    return isPrivateIp(v4);
  }
  return false;
}

function hostAllowed(hostname) {
  if (ALLOWED_DOWNLOAD_HOSTS.length === 0) return true;
  const h = hostname.toLowerCase();
  for (const pattern of ALLOWED_DOWNLOAD_HOSTS) {
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(1); // ".example.com"
      if (h === suffix.slice(1) || h.endsWith(suffix)) return true;
    } else if (h === pattern) {
      return true;
    }
  }
  return false;
}

async function assertSafeUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL");
  }
  if (parsed.protocol !== "https:" && !(ALLOW_HTTP_DOWNLOADS && parsed.protocol === "http:")) {
    throw new Error(`Unsupported URL scheme: ${parsed.protocol}`);
  }
  const hostname = parsed.hostname;
  if (!hostname) throw new Error("URL has no hostname");
  if (!hostAllowed(hostname)) {
    throw new Error(`Hostname not allowed: ${hostname}`);
  }
  // If the hostname is already a literal IP, check it directly.
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      throw new Error(`Refusing to fetch private/loopback IP: ${hostname}`);
    }
    return;
  }
  // Otherwise resolve and verify every address.
  let records;
  try {
    records = await dns.lookup(hostname, { all: true });
  } catch (err) {
    throw new Error(`DNS lookup failed for ${hostname}: ${err.code || err.message}`);
  }
  for (const rec of records) {
    if (isPrivateIp(rec.address)) {
      throw new Error(
        `Refusing to fetch ${hostname} — resolves to private/loopback ${rec.address}`
      );
    }
  }
}

// --- output_key validation ---
//
// `output_key` is attacker-influenced and used verbatim as an R2 object key.
// Without validation, a caller can overwrite any existing object (e.g.
// already-published creative videos). Force a predictable shape so keys can
// only land under expected prefixes and can only hold expected extensions.
const OUTPUT_KEY_RE = /^[a-zA-Z0-9][a-zA-Z0-9/_.\-]{0,199}\.(mp4|jpg|jpeg|png|webp)$/;

function validateOutputKey(key) {
  if (typeof key !== "string") return "output_key must be a string";
  if (!OUTPUT_KEY_RE.test(key)) return "output_key has invalid shape";
  if (key.includes("..")) return "output_key must not contain '..'";
  if (key.startsWith("/")) return "output_key must not start with '/'";
  return null;
}

const MAX_REDIRECTS = 3;

async function download(url, dest) {
  // Manual redirect loop so each hop is SSRF-validated (the auto-follow
  // behaviour of `fetch` would happily chase a 302 → http://169.254.169.254).
  let current = url;
  let res;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    await assertSafeUrl(current);
    try {
      res = await fetch(current, {
        redirect: "manual",
        signal: AbortSignal.timeout(60_000),
      });
    } catch (err) {
      const cause =
        err?.cause?.code ||
        err?.cause?.errno ||
        err?.cause?.message ||
        err?.message ||
        "unknown";
      const short = current.length > 120 ? current.slice(0, 120) + "…" : current;
      throw new Error(`Network error fetching ${short}: ${cause}`);
    }
    if (res.status >= 300 && res.status < 400) {
      const next = res.headers.get("location");
      if (!next) throw new Error(`Redirect ${res.status} without Location`);
      // Resolve relative Location against current URL.
      current = new URL(next, current).toString();
      continue;
    }
    break;
  }
  if (!res.ok) {
    const short = current.length > 120 ? current.slice(0, 120) + "…" : current;
    throw new Error(`HTTP ${res.status} fetching ${short}`);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  await fsp.writeFile(dest, buf);
}

async function uploadToR2(localPath, key, contentType) {
  const r2 = getR2();
  const body = await fsp.readFile(localPath);
  await r2.send(
    new PutObjectCommand({
      Bucket: BUCKET,
      Key: key,
      Body: body,
      ContentType: contentType || "video/mp4",
    })
  );
  return `${R2_PUBLIC_URL}/${key}`;
}

async function cleanup(...files) {
  for (const f of files) {
    await fsp.unlink(f).catch(() => {});
  }
}

// --- ffprobe helpers ---

async function getDuration(filePath) {
  const { stdout } = await exec("ffprobe", [
    "-v", "quiet",
    "-show_entries", "format=duration",
    "-of", "csv=p=0",
    filePath,
  ]);
  return parseFloat(stdout.trim());
}

async function getVideoDimensions(filePath) {
  const { stdout } = await exec("ffprobe", [
    "-v", "quiet",
    "-select_streams", "v:0",
    "-show_entries", "stream=width,height",
    "-of", "csv=p=0",
    filePath,
  ]);
  const [w, h] = stdout.trim().split(",").map((n) => parseInt(n, 10));
  return { width: w, height: h };
}

async function hasAudioStream(filePath) {
  try {
    const { stdout } = await exec("ffprobe", [
      "-v", "quiet",
      "-select_streams", "a",
      "-show_entries", "stream=codec_type",
      "-of", "csv=p=0",
      filePath,
    ]);
    return stdout.trim().length > 0;
  } catch {
    return false;
  }
}

// --- Auth middleware ---

function auth(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (token !== AUTH_TOKEN) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// --- Health check ---

app.get("/health", (_req, res) => {
  res.json({ status: "ok", ffmpeg: true });
});

// --- POST /overlay ---
// Overlay audio onto video clip (VO mode)

app.post("/overlay", auth, async (req, res) => {
  const { video_url, audio_url, output_key } = req.body;
  if (!video_url || !audio_url || !output_key) {
    return res.status(400).json({ error: "video_url, audio_url, output_key required" });
  }
  const keyErr = validateOutputKey(output_key);
  if (keyErr) return res.status(400).json({ error: keyErr });

  const videoFile = tmpPath(".mp4");
  const audioFile = tmpPath(".mp3");
  const audioTrimmed = tmpPath(".mp3");
  const outputFile = tmpPath(".mp4");

  try {
    await Promise.all([
      download(video_url, videoFile),
      download(audio_url, audioFile),
    ]);

    const [videoDur, audioDur] = await Promise.all([
      getDuration(videoFile),
      getDuration(audioFile),
    ]);

    let audioFinal = audioFile;

    // Trim audio if longer than video (0.3s tolerance)
    if (audioDur > videoDur + 0.3) {
      await exec("ffmpeg", [
        "-y", "-i", audioFile,
        "-t", String(videoDur),
        audioTrimmed,
      ]);
      audioFinal = audioTrimmed;
    }

    await exec("ffmpeg", [
      "-y", "-i", videoFile, "-i", audioFinal,
      "-filter_complex", "[1:a]apad[aout]",
      "-map", "0:v", "-map", "[aout]",
      "-c:v", "copy", "-c:a", "aac", "-shortest",
      outputFile,
    ]);

    const url = await uploadToR2(outputFile, output_key, "video/mp4");
    const duration = await getDuration(outputFile);

    res.json({ url, duration, output_key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    await cleanup(videoFile, audioFile, audioTrimmed, outputFile);
  }
});

// --- POST /merge ---
// Merge N clips with fadeblack transitions

// Hard ceiling matches Kling's 15s per-clip cap × a generous shot count.
// 30 clips × 15s = ~7.5 min final, more than any real Facebook ad needs.
const MAX_CLIPS_PER_MERGE = 30;

app.post("/merge", auth, async (req, res) => {
  const { clips, output_key, transition_duration } = req.body;
  if (!clips || !Array.isArray(clips) || clips.length < 1 || !output_key) {
    return res.status(400).json({ error: "clips[] and output_key required" });
  }
  if (clips.length > MAX_CLIPS_PER_MERGE) {
    return res.status(400).json({ error: `Too many clips (${clips.length}). Max ${MAX_CLIPS_PER_MERGE}.` });
  }
  for (let i = 0; i < clips.length; i++) {
    if (!clips[i] || typeof clips[i].url !== "string" || !clips[i].url) {
      return res.status(400).json({ error: `clips[${i}].url is required` });
    }
  }
  const mergeKeyErr = validateOutputKey(output_key);
  if (mergeKeyErr) return res.status(400).json({ error: mergeKeyErr });

  const TRANSITION = transition_duration || 0.4;
  const clipFiles = clips.map(() => tmpPath(".mp4"));
  const normFiles = clips.map(() => tmpPath(".mp4"));
  const outputFile = tmpPath(".mp4");

  try {
    // Download all clips
    await Promise.all(clips.map((c, i) => download(c.url, clipFiles[i])));

    // Check audio per clip. The pipeline mixes Kling clips (with VO) and
    // /still-to-clip outputs (silent) freely, so we cannot assume the first
    // clip's audio state applies to all. If ANY clip has audio, every clip
    // is normalized to a stereo/48kHz track — silent ones get an anullsrc
    // fill — so the acrossfade chain always finds [i:a] on every input.
    const perClipAudio = await Promise.all(clipFiles.map(hasAudioStream));
    const anyHasAudio = perClipAudio.some(Boolean);

    const durations = [];
    for (let i = 0; i < clipFiles.length; i++) {
      const normArgs = ["-y", "-i", clipFiles[i]];
      if (anyHasAudio && !perClipAudio[i]) {
        // Inject silent stereo track so this clip carries audio through merge.
        normArgs.push("-f", "lavfi", "-i", "anullsrc=channel_layout=stereo:sample_rate=48000");
      }
      normArgs.push("-vf", "fps=24");
      if (anyHasAudio) {
        if (perClipAudio[i]) {
          // Real audio — force stereo + 48kHz so acrossfade never errors on
          // mismatched channel layouts when one clip is mono, another stereo.
          normArgs.push("-af", "aformat=channel_layouts=stereo:sample_rates=48000");
        }
        normArgs.push(
          "-map", "0:v",
          "-map", perClipAudio[i] ? "0:a" : "1:a",
          "-shortest",
          "-ac", "2", "-ar", "48000",
          "-c:v", "libx264", "-c:a", "aac",
        );
      } else {
        normArgs.push("-c:v", "libx264", "-an");
      }
      normArgs.push(normFiles[i]);
      await exec("ffmpeg", normArgs);
      durations.push(await getDuration(normFiles[i]));
    }

    const n = normFiles.length;

    if (n === 1) {
      await fsp.copyFile(normFiles[0], outputFile);
    } else {
      // Build ffmpeg filter_complex for xfade chain
      const inputs = [];
      for (const nf of normFiles) {
        inputs.push("-i", nf);
      }

      const videoFilters = [];
      const audioFilters = [];

      for (let i = 0; i < n - 1; i++) {
        const offset = durations.slice(0, i + 1).reduce((a, b) => a + b, 0) - TRANSITION * (i + 1);
        const vIn = i === 0 ? "[0:v][1:v]" : `[v${i - 1}][${i + 1}:v]`;
        const vOut = i === n - 2 ? "[v]" : `[v${i}]`;

        videoFilters.push(`${vIn}xfade=transition=fadeblack:duration=${TRANSITION}:offset=${offset.toFixed(3)}${vOut}`);

        if (anyHasAudio) {
          const aIn = i === 0 ? "[0:a][1:a]" : `[a${i - 1}][${i + 1}:a]`;
          const aOut = i === n - 2 ? "[a]" : `[a${i}]`;
          audioFilters.push(`${aIn}acrossfade=d=${TRANSITION}${aOut}`);
        }
      }

      const filterComplex = [...videoFilters, ...audioFilters].join(";");

      const mergeArgs = [
        "-y",
        ...inputs,
        "-filter_complex", filterComplex,
        "-map", "[v]",
      ];

      if (anyHasAudio) {
        mergeArgs.push("-map", "[a]", "-c:a", "aac", "-ar", "44100");
      }

      mergeArgs.push(
        "-c:v", "libx264", "-profile:v", "baseline", "-level", "3.1",
        "-pix_fmt", "yuv420p", "-crf", "18", "-preset", "fast",
        outputFile,
      );

      await exec("ffmpeg", mergeArgs);
    }

    const url = await uploadToR2(outputFile, output_key, "video/mp4");
    const duration = await getDuration(outputFile);

    res.json({ url, duration, output_key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    await cleanup(...clipFiles, ...normFiles, outputFile);
  }
});

// --- POST /still-to-clip ---
// Convert a static image into a silent mp4 of exactly `duration_sec` length.
// Output is 720x1280 (9:16) with black padding if the input has a different
// aspect ratio, and is encoded with the same codec/profile/fps as /merge's
// normalization step so the resulting clip xfades cleanly with Kling outputs.

app.post("/still-to-clip", auth, async (req, res) => {
  const { image_url, duration_sec, output_key } = req.body;
  if (!image_url || !duration_sec || !output_key) {
    return res.status(400).json({ error: "image_url, duration_sec, output_key required" });
  }
  const keyErr = validateOutputKey(output_key);
  if (keyErr) return res.status(400).json({ error: keyErr });

  const duration = Math.max(0.5, Math.min(60, Number(duration_sec)));
  const imageFile = tmpPath(".img");
  const outputFile = tmpPath(".mp4");

  try {
    await download(image_url, imageFile);

    await exec("ffmpeg", [
      "-y",
      "-loop", "1",
      "-i", imageFile,
      "-t", String(duration),
      "-vf",
        "scale=720:1280:force_original_aspect_ratio=decrease," +
        "pad=720:1280:(ow-iw)/2:(oh-ih)/2:black," +
        "fps=24",
      "-c:v", "libx264", "-profile:v", "baseline", "-level", "3.1",
      "-pix_fmt", "yuv420p", "-crf", "18", "-preset", "fast",
      "-an",
      outputFile,
    ]);

    const url = await uploadToR2(outputFile, output_key, "video/mp4");
    const realDuration = await getDuration(outputFile);
    res.json({ url, duration: realDuration, output_key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    await cleanup(imageFile, outputFile);
  }
});

// --- POST /burn-subs ---
// Burn styled ASS subtitles into video.
//
// Body: { video_url, output_key, style?, language?, words? }
//
// Supported styles:
//   bold_outline — large white text, thick black outline (default / UGC standard)
//   karaoke     — word-by-word yellow highlight on white text
//   boxed       — white text on semi-transparent black box
//   glowing     — white text with colored neon glow (pink)
//   popup       — word-by-word scale-in animation
//
// If `words` is not provided, the endpoint auto-transcribes via Cloudflare
// Whisper. `language` defaults to "fr".

// ─── Subtitle style definitions ────────────────────────────────────────
// Each style returns the [V4+ Styles] block and a function that formats
// each dialogue line (some styles need per-word override tags).
//
// ASS color format: &HAABBGGRR (alpha, blue, green, red — reversed from RGB).
// BorderStyle=1 = outline+shadow, BorderStyle=3 = opaque box behind text.

const SUBTITLE_STYLE_DEFS = {
  // Large white, thick black outline — the UGC/performance ad standard.
  bold_outline: {
    styleLine:
      "Style: Default,Arial,48,&H00FFFFFF,&H000000FF,&H00000000,&H80000000,1,0,0,0,100,100,0,0,1,3.5,0,2,10,10,170,1",
    formatDialogue(start, end, text) {
      return `Dialogue: 0,${toAssTime(start)},${toAssTime(end)},Default,,0,0,0,,${text}`;
    },
  },

  // Word-by-word highlight: white text, active word turns yellow.
  // Uses ASS \\k (karaoke) tags with per-word durations.
  karaoke: {
    styleLine:
      "Style: Default,Arial,48,&H00FFFFFF,&H0000FFFF,&H00000000,&H80000000,1,0,0,0,100,100,0,0,1,3,0,2,10,10,170,1",
    // Karaoke needs the raw word list, not pre-joined chunks.
    // formatDialogue is called per-chunk but we override in buildAssContent.
    formatDialogue(start, end, text) {
      return `Dialogue: 0,${toAssTime(start)},${toAssTime(end)},Default,,0,0,0,,${text}`;
    },
  },

  // White text on a semi-transparent black box. Maximum readability.
  boxed: {
    // BorderStyle=3 → opaque box. BackColour alpha controls box opacity.
    styleLine:
      "Style: Default,Arial,42,&H00FFFFFF,&H000000FF,&H00000000,&H96000000,1,0,0,0,100,100,0,0,3,0,4,2,20,20,170,1",
    formatDialogue(start, end, text) {
      return `Dialogue: 0,${toAssTime(start)},${toAssTime(end)},Default,,0,0,0,,${text}`;
    },
  },

  // White text with colored glow (pink neon). Uses blur + colored shadow.
  glowing: {
    styleLine:
      "Style: Default,Arial,46,&H00FFFFFF,&H000000FF,&H00CC44FF,&H00CC44FF,1,0,0,0,100,100,0,0,1,2,3,2,10,10,170,1",
    formatDialogue(start, end, text) {
      // \\blur4 gives a soft glow around each letter
      return `Dialogue: 0,${toAssTime(start)},${toAssTime(end)},Default,,0,0,0,,{\\blur4}${text}`;
    },
  },

  // Word-by-word scale-in pop animation. Each word fades+scales in.
  popup: {
    styleLine:
      "Style: Default,Arial,48,&H00FFFFFF,&H000000FF,&H00000000,&H80000000,1,0,0,0,100,100,0,0,1,3,0,2,10,10,170,1",
    formatDialogue(start, end, text) {
      return `Dialogue: 0,${toAssTime(start)},${toAssTime(end)},Default,,0,0,0,,${text}`;
    },
  },
};

// Build the full ASS file content given a style key, word-level timing,
// and a chunk size for grouping words into subtitle lines.
function buildAssContent(styleKey, wordList) {
  const def = SUBTITLE_STYLE_DEFS[styleKey] || SUBTITLE_STYLE_DEFS.bold_outline;

  const header = `[Script Info]
ScriptType: v4.00+
PlayResX: 720
PlayResY: 1280
ScaledBorderAndShadow: yes

[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
${def.styleLine}

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
`;

  const lines = [];

  if (styleKey === "karaoke") {
    // Karaoke: group 4 words per line, use \kf tags for smooth fill.
    // \kf duration is in centiseconds.
    const chunks = chunkWords(wordList, 4);
    for (const chunk of chunks) {
      const chunkStart = chunk[0].start;
      const chunkEnd = chunk[chunk.length - 1].end;
      const karaTags = chunk
        .map((w) => {
          const durCs = Math.round((w.end - w.start) * 100);
          return `{\\kf${durCs}}${w.word}`;
        })
        .join(" ");
      lines.push(
        `Dialogue: 0,${toAssTime(chunkStart)},${toAssTime(chunkEnd)},Default,,0,0,0,,${karaTags}`
      );
    }
  } else if (styleKey === "popup") {
    // Pop-up: each word appears individually with a scale-in animation.
    // \fscx0\fscy0 → \fscx100\fscy100 over 80ms = snappy pop.
    for (const w of wordList) {
      const animDur = 80; // ms
      const tag = `{\\fscx0\\fscy0\\t(0,${animDur},\\fscx100\\fscy100)}`;
      lines.push(
        `Dialogue: 0,${toAssTime(w.start)},${toAssTime(w.end)},Default,,0,0,0,,${tag}${w.word}`
      );
    }
  } else {
    // All other styles: group 4 words per line, plain text.
    const chunks = chunkWords(wordList, 4);
    for (const chunk of chunks) {
      const text = chunk.map((w) => w.word).join(" ");
      lines.push(def.formatDialogue(chunk[0].start, chunk[chunk.length - 1].end, text));
    }
  }

  return { content: header + lines.join("\n") + "\n", chunkCount: lines.length };
}

// Group word-level timing into N-word chunks for subtitle lines.
function chunkWords(wordList, size) {
  const chunks = [];
  for (let i = 0; i < wordList.length; i += size) {
    chunks.push(wordList.slice(i, i + size));
  }
  return chunks;
}

app.post("/burn-subs", auth, async (req, res) => {
  const { video_url, words, output_key, language, style } = req.body;

  if (!video_url || !output_key) {
    return res.status(400).json({ error: "video_url and output_key required" });
  }
  const keyErr = validateOutputKey(output_key);
  if (keyErr) return res.status(400).json({ error: keyErr });

  const styleKey = style && SUBTITLE_STYLE_DEFS[style] ? style : "bold_outline";
  const videoFile = tmpPath(".mp4");
  const assFile = tmpPath(".ass");
  const audioTmp = tmpPath(".mp3");
  const outputFile = tmpPath(".mp4");

  // Guards the catch-block fallback: once the burned-subs output has been
  // uploaded to R2, a later error must NOT re-upload the raw source video
  // over it (which would clobber the good output with an un-subtitled one).
  let uploadedFinal = false;

  try {
    await download(video_url, videoFile);

    let wordList = words;

    // If no words provided, transcribe via Cloudflare Whisper
    if (!wordList) {
      const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
      const apiToken = process.env.CLOUDFLARE_API_TOKEN;

      if (!accountId || !apiToken) {
        const url = await uploadToR2(videoFile, output_key, "video/mp4");
        return res.json({ url, output_key, subtitles: false });
      }

      await exec("ffmpeg", [
        "-y", "-i", videoFile,
        "-vn", "-ar", "16000", "-ac", "1", "-f", "mp3",
        audioTmp,
      ]);

      const audioData = await fsp.readFile(audioTmp);
      const lang = language || "fr";

      const formData = new FormData();
      formData.append("file", new Blob([audioData], { type: "audio/mpeg" }), "audio.mp3");
      formData.append("task", "transcribe");
      formData.append("language", lang);
      formData.append("vtt", "true");

      const whisperRes = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}/ai/run/@cf/openai/whisper`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${apiToken}` },
          body: formData,
        }
      );

      if (!whisperRes.ok) {
        const url = await uploadToR2(videoFile, output_key, "video/mp4");
        return res.json({ url, output_key, subtitles: false, reason: "whisper_failed" });
      }

      const whisperData = await whisperRes.json();
      wordList = whisperData.result?.words;

      if (!wordList || wordList.length === 0) {
        const url = await uploadToR2(videoFile, output_key, "video/mp4");
        return res.json({ url, output_key, subtitles: false, reason: "no_words" });
      }
    }

    const { content: assContent, chunkCount } = buildAssContent(styleKey, wordList);
    await fsp.writeFile(assFile, assContent, "utf-8");

    await exec("ffmpeg", [
      "-y",
      "-i", videoFile,
      "-vf", `ass=${assFile}`,
      "-c:v", "libx264", "-profile:v", "baseline", "-level", "3.1",
      "-pix_fmt", "yuv420p", "-crf", "18", "-preset", "fast",
      "-c:a", "copy",
      outputFile,
    ]);

    const url = await uploadToR2(outputFile, output_key, "video/mp4");
    uploadedFinal = true;
    const duration = await getDuration(outputFile);

    res.json({ url, duration, output_key, subtitles: true, style: styleKey, chunks: chunkCount });
  } catch (err) {
    // Only fall back to raw-video upload if we never uploaded the burned-subs
    // output. Otherwise a post-upload error (e.g. getDuration crash) would
    // overwrite the good output with the un-subtitled source.
    if (uploadedFinal) {
      res.status(500).json({ error: err.message });
    } else {
      try {
        const url = await uploadToR2(videoFile, output_key, "video/mp4");
        res.json({ url, output_key, subtitles: false, reason: err.message });
      } catch {
        res.status(500).json({ error: err.message });
      }
    }
  } finally {
    await cleanup(videoFile, assFile, audioTmp, outputFile);
  }
});

function toAssTime(s) {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return `${h}:${String(m).padStart(2, "0")}:${sec.toFixed(2).padStart(5, "0")}`;
}

// --- POST /mix-background ---
// Mix background music into a video at reduced volume (-18dB).
// Music loops if shorter than video, fades out over the last 3s.

app.post("/mix-background", auth, async (req, res) => {
  const { video_url, music_url, output_key } = req.body;
  if (!video_url || !music_url || !output_key) {
    return res.status(400).json({ error: "video_url, music_url, output_key required" });
  }
  const keyErr = validateOutputKey(output_key);
  if (keyErr) return res.status(400).json({ error: keyErr });

  const videoFile = tmpPath(".mp4");
  const musicFile = tmpPath(".mp3");
  const outputFile = tmpPath(".mp4");

  try {
    await Promise.all([
      download(video_url, videoFile),
      download(music_url, musicFile),
    ]);

    const videoDuration = await getDuration(videoFile);

    // Build audio filter:
    // 1. Loop music, trim to video length
    // 2. Reduce volume by 18dB
    // 3. Fade out over last 3s
    const fadeStart = Math.max(0, videoDuration - 3);
    const musicFilter = `[1:a]aloop=loop=-1:size=2e+09,atrim=0:${videoDuration.toFixed(3)},volume=0.125,afade=t=out:st=${fadeStart.toFixed(3)}:d=3[bgm]`;

    const hasAudio = await hasAudioStream(videoFile);

    let filterComplex;
    if (hasAudio) {
      // Mix existing audio with background music
      filterComplex = `${musicFilter};[0:a][bgm]amix=inputs=2:duration=first:dropout_transition=0[aout]`;
    } else {
      // No existing audio — just use background music
      filterComplex = `${musicFilter};[bgm]acopy[aout]`;
    }

    await exec("ffmpeg", [
      "-i", videoFile,
      "-i", musicFile,
      "-filter_complex", filterComplex,
      "-map", "0:v",
      "-map", "[aout]",
      "-c:v", "copy",
      "-c:a", "aac",
      "-b:a", "128k",
      "-shortest",
      "-y", outputFile,
    ]);

    const url = await uploadToR2(outputFile, output_key, "video/mp4");
    const duration = await getDuration(outputFile);
    res.json({ url, duration, output_key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    await cleanup(videoFile, musicFile, outputFile);
  }
});

// --- POST /extract-thumbnail ---
// Extract a single JPG frame at `timestamp_sec` (default 1s), upload to R2.
// Returns thumbnail URL + source video width/height/duration so the caller
// can derive aspect_ratio for creatives.

app.post("/extract-thumbnail", auth, async (req, res) => {
  const { video_url, output_key, timestamp_sec } = req.body;
  if (!video_url || !output_key) {
    return res.status(400).json({ error: "video_url, output_key required" });
  }
  const keyErr = validateOutputKey(output_key);
  if (keyErr) return res.status(400).json({ error: keyErr });

  const videoFile = tmpPath(".mp4");
  const thumbFile = tmpPath(".jpg");

  try {
    await download(video_url, videoFile);

    const [duration, dims] = await Promise.all([
      getDuration(videoFile),
      getVideoDimensions(videoFile),
    ]);

    // Clamp timestamp to well inside the clip so we never seek past EOF.
    const ts = Math.min(Math.max(timestamp_sec ?? 1, 0), Math.max(0, duration - 0.1));

    await exec("ffmpeg", [
      "-y",
      "-ss", String(ts),
      "-i", videoFile,
      "-frames:v", "1",
      "-q:v", "3",
      thumbFile,
    ]);

    const url = await uploadToR2(thumbFile, output_key, "image/jpeg");
    res.json({ url, width: dims.width, height: dims.height, duration });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    await cleanup(videoFile, thumbFile);
  }
});

// --- Start ---

const PORT = process.env.PORT || 3000;
// Default-bind to 127.0.0.1 so the service is not reachable from the public
// internet. Front with nginx (TLS + IP allowlist of Vercel egress) on the
// VPS. Override with LISTEN_HOST=0.0.0.0 only if you really need that.
const HOST = process.env.LISTEN_HOST || "127.0.0.1";
app.listen(PORT, HOST, () =>
  console.log(`ffmpeg-service listening on ${HOST}:${PORT}`)
);
