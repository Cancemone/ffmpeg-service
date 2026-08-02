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
const { assertStorageEnv, uploadFile } = require("./storage");

const execRaw = promisify(execFile);

// Hard per-invocation timeouts on child processes. Without these a single
// wedged ffmpeg/ffprobe would hold CPU/RAM on the VPS indefinitely, long
// after the Vercel caller has already timed out. killSignal: "SIGKILL"
// because ffmpeg ignores SIGTERM in some codepaths.
const FFPROBE_TIMEOUT_MS = 15_000;
const FFMPEG_TIMEOUT_MS = 300_000; // 5 min — covers worst-case 30-clip merge

// Strip ALL metadata from every video output we produce. `-map_metadata -1`
// drops input-derived global/stream tags (title, comment, GPS, source
// device); `-fflags +bitexact` stops the mp4 muxer from auto-stamping its
// own `encoder` (Lavf…) + `creation_time` tags. Spliced in right before the
// output file path of each video-producing ffmpeg call so whatever ends up
// being the final delivered file is clean regardless of which stage produced
// it. Meta re-encodes uploads and discards container metadata anyway — this
// is delivery hygiene (no cross-creative fingerprint via tags), not a visual
// change. Negligible cost: no extra pass, just output flags.
const CLEAN_META = ["-map_metadata", "-1", "-fflags", "+bitexact"];

// Color-grade presets → ffmpeg video filter chains. Keys mirror ColorGrade in
// lib/flows/types.ts (minus 'none', which the caller never sends here). Kept
// deliberately mild — these run on already-generated UGC, not raw footage, so
// over-grading reads as fake. `eq` for contrast/saturation/gamma, optional
// `colorbalance` for tone, light `unsharp` on punchy for that "shot on phone"
// crispness.
const COLOR_GRADE_FILTERS = {
  warm_ugc:
    "eq=contrast=1.06:saturation=1.10:gamma=1.02,colorbalance=rm=0.04:gm=0.01:bm=-0.05",
  punchy:
    "eq=contrast=1.16:saturation=1.22:brightness=0.02:gamma=0.98,unsharp=5:5:0.4:5:5:0.0",
  cool_clean:
    "eq=contrast=1.05:saturation=1.02:gamma=1.00,colorbalance=rm=-0.04:gm=0.00:bm=0.05",
};

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
    const tail = stderr.slice(-6000).trim();
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

try {
  assertStorageEnv();
} catch (err) {
  console.error(`FATAL: ${err.message}. Refusing to start.`);
  process.exit(1);
}

function tmpPath(ext) {
  return path.join(os.tmpdir(), `ff_${crypto.randomBytes(6).toString("hex")}${ext}`);
}

// --- SSRF protection ---
//
// `download()` fetches attacker-influenced URLs (creative video URLs, music
// URLs, thumbnail sources). Without validation, a caller can point us at
// cloud metadata (169.254.169.254), localhost services, or LAN hosts — the
// body would then be uploaded to storage, making this an exfiltration channel.
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

const {
  validateOutputKey,
  parseDimensions,
  scaleAndPadFilter,
  isPrivateIp,
  parseHostPatterns,
  hostAllowed,
} = require("./validation");
const { buildAssContent, STYLES } = require("./subtitles");
const {
  MERGE_TRANSITION_SEC,
  OVERLAY_MAX_OVERFLOW_SEC,
  overlayAudioOverflow,
} = require("./audio-fit");

const ALLOW_HTTP_DOWNLOADS = process.env.ALLOW_HTTP_DOWNLOADS === "true";
const ALLOWED_DOWNLOAD_HOSTS = parseHostPatterns(process.env.ALLOWED_DOWNLOAD_HOSTS);

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
  if (!hostAllowed(hostname, ALLOWED_DOWNLOAD_HOSTS)) {
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

    // The Vercel-side bake sizes the audio to the video before sending it here
    // (atempo / TTS-speed re-bake / script adjust), so audio > video means that
    // fit is wrong — and the `-t videoDur` below would cut the overrun off the
    // END of the ad, which is where the CTA is. That used to happen silently:
    // this endpoint trimmed to fit and answered 200, so a broken fit was
    // indistinguishable from a correct one and nobody read the returned
    // duration. Same policy as /burn-subs: a service-visible fault fails loudly
    // and the caller decides whether to retry. Sub-tolerance slop is still
    // absorbed by -t — see OVERLAY_MAX_OVERFLOW_SEC for why the line is there.
    const fit = overlayAudioOverflow(audioDur, videoDur);
    if (fit.exceedsTolerance) {
      console.error(
        `[overlay] audio overruns video by ${fit.overflowSec}s ` +
        `(audio=${audioDur}s video=${videoDur}s tolerance=${OVERLAY_MAX_OVERFLOW_SEC}s) output_key=${output_key}`
      );
      return res.status(400).json({
        error:
          `audio is ${fit.overflowSec}s longer than the video ` +
          `(audio ${audioDur}s vs video ${videoDur}s, tolerance ${OVERLAY_MAX_OVERFLOW_SEC}s). ` +
          "Trimming it would cut the end of the ad — fit the audio before calling /overlay.",
        audio_overflow_sec: fit.overflowSec,
        audio_duration: audioDur,
        video_duration: videoDur,
      });
    }

    await exec("ffmpeg", [
      "-y", "-i", videoFile, "-i", audioFile,
      // apad makes the audio stream infinite so a VO shorter than the
      // clip is padded with silence instead of cutting the video. The
      // output is then hard-bounded by -t to videoDur: relying on
      // -shortest alone hangs forever against a -c:v copy stream on
      // some ffmpeg builds (apad never EOFs, copy stream never trips
      // -shortest), which previously ran until the 300s SIGKILL.
      "-filter_complex", "[1:a]apad[aout]",
      "-map", "0:v", "-map", "[aout]",
      "-c:v", "copy", "-c:a", "aac",
      "-t", String(videoDur),
      ...CLEAN_META,
      outputFile,
    ]);

    const url = await uploadFile(outputFile, output_key, "video/mp4");
    const duration = await getDuration(outputFile);

    res.json({ url, duration, output_key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    await cleanup(videoFile, audioFile, outputFile);
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

  const dims = parseDimensions(req.body);
  if (dims.error) return res.status(400).json({ error: dims.error });

  const TRANSITION = transition_duration || MERGE_TRANSITION_SEC;
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
      // Force identical geometry / SAR / pixel format / fps on every clip.
      // xfade aborts on init if any of (width, height, format, SAR, timebase)
      // differ between its two inputs — Kling outputs and /still-to-clip
      // outputs used to disagree on SAR / pix_fmt even when both were 720x1280.
      normArgs.push("-vf", scaleAndPadFilter(dims.width, dims.height));
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
          "-c:v", "libx264", "-profile:v", "baseline", "-level", "3.1",
          "-pix_fmt", "yuv420p",
          "-c:a", "aac",
        );
      } else {
        normArgs.push(
          "-c:v", "libx264", "-profile:v", "baseline", "-level", "3.1",
          "-pix_fmt", "yuv420p",
          "-an",
        );
      }
      normArgs.push(...CLEAN_META, normFiles[i]);
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

      // Each xfade starts the next clip TRANSITION seconds before the previous
      // one ends, so the junctions OVERLAP and the output runs
      // sum(durations) - TRANSITION * (n - 1) — shorter than the raw sum. The
      // caller relies on that identity when it sizes the global VO mp3 (see
      // mergedTimelineDuration in creative-studio); if this recurrence ever
      // changes, that math has to change with it.
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
        ...CLEAN_META,
        outputFile,
      );

      await exec("ffmpeg", mergeArgs);
    }

    const url = await uploadFile(outputFile, output_key, "video/mp4");
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
// Output is scaled/padded to the requested (or default 720x1280) dimensions
// via the same scaleAndPadFilter chain /merge uses, so the resulting clip
// xfades cleanly with Kling outputs (setsar=1/format=yuv420p included —
// previously this endpoint omitted both, which is what made stills and Kling
// clips disagree on SAR/pix_fmt at merge time).

app.post("/still-to-clip", auth, async (req, res) => {
  const { image_url, duration_sec, output_key } = req.body;
  if (!image_url || !duration_sec || !output_key) {
    return res.status(400).json({ error: "image_url, duration_sec, output_key required" });
  }
  const keyErr = validateOutputKey(output_key);
  if (keyErr) return res.status(400).json({ error: keyErr });

  const dims = parseDimensions(req.body);
  if (dims.error) return res.status(400).json({ error: dims.error });

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
      "-vf", `${scaleAndPadFilter(dims.width, dims.height)}`,
      "-c:v", "libx264", "-profile:v", "baseline", "-level", "3.1",
      "-pix_fmt", "yuv420p", "-crf", "18", "-preset", "fast",
      "-an",
      ...CLEAN_META,
      outputFile,
    ]);

    const url = await uploadFile(outputFile, output_key, "video/mp4");
    const realDuration = await getDuration(outputFile);
    res.json({ url, duration: realDuration, output_key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    await cleanup(imageFile, outputFile);
  }
});

// --- POST /extract-audio ---
// Extract the audio track from a video into mp3, upload to storage, return URL.
// Used by the Next.js side to feed kie.ai Scribe (STT) with an audio_url
// — Scribe accepts only audio formats, not mp4. 22050 Hz mono @ 64 kbps
// keeps file size small (a 60s clip ≈ 500 KB) while preserving enough
// fidelity for accurate word-level transcription.
//
// Body: { video_url, output_key }
// Response: { url, output_key }
app.post("/extract-audio", auth, async (req, res) => {
  const { video_url, output_key } = req.body;
  if (!video_url || !output_key) {
    return res.status(400).json({ error: "video_url and output_key required" });
  }
  const keyErr = validateOutputKey(output_key);
  if (keyErr) return res.status(400).json({ error: keyErr });

  const videoFile = tmpPath(".mp4");
  const audioFile = tmpPath(".mp3");

  try {
    await download(video_url, videoFile);
    await exec("ffmpeg", [
      "-y", "-i", videoFile,
      "-vn",
      "-ar", "22050",
      "-ac", "1",
      "-b:a", "64k",
      "-f", "mp3",
      audioFile,
    ]);
    const url = await uploadFile(audioFile, output_key, "audio/mpeg");
    res.json({ url, output_key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    await cleanup(videoFile, audioFile);
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

app.post("/burn-subs", auth, async (req, res) => {
  const { video_url, words, output_key, language, style } = req.body;

  if (!video_url || !output_key) {
    return res.status(400).json({ error: "video_url and output_key required" });
  }
  const keyErr = validateOutputKey(output_key);
  if (keyErr) return res.status(400).json({ error: keyErr });

  const styleKey = style && STYLES[style] ? style : "bold_outline";
  const videoFile = tmpPath(".mp4");
  const assFile = tmpPath(".ass");
  const audioTmp = tmpPath(".mp3");
  const outputFile = tmpPath(".mp4");

  try {
    await download(video_url, videoFile);

    let wordList = words;

    // If no words provided, transcribe via Cloudflare Whisper
    if (!wordList) {
      const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
      const apiToken = process.env.CLOUDFLARE_API_TOKEN;

      if (!accountId || !apiToken) {
        const url = await uploadFile(videoFile, output_key, "video/mp4");
        return res.json({ url, output_key, subtitles: false, reason: "no_whisper_creds" });
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
        const url = await uploadFile(videoFile, output_key, "video/mp4");
        return res.json({ url, output_key, subtitles: false, reason: "whisper_failed" });
      }

      const whisperData = await whisperRes.json();
      wordList = whisperData.result?.words;

      if (!wordList || wordList.length === 0) {
        const url = await uploadFile(videoFile, output_key, "video/mp4");
        return res.json({ url, output_key, subtitles: false, reason: "no_words" });
      }
    }

    const dims = await getVideoDimensions(videoFile);
    const { content: assContent, chunkCount } = buildAssContent(styleKey, wordList, dims);
    await fsp.writeFile(assFile, assContent, "utf-8");

    await exec("ffmpeg", [
      "-y",
      "-i", videoFile,
      "-vf", `ass=${assFile}`,
      "-c:v", "libx264", "-profile:v", "baseline", "-level", "3.1",
      "-pix_fmt", "yuv420p", "-crf", "18", "-preset", "fast",
      "-c:a", "copy",
      ...CLEAN_META,
      outputFile,
    ]);

    const url = await uploadFile(outputFile, output_key, "video/mp4");
    const duration = await getDuration(outputFile);

    res.json({ url, duration, output_key, subtitles: true, style: styleKey, chunks: chunkCount });
  } catch (err) {
    // No raw-video fallback here, deliberately. The three `subtitles: false`
    // returns above are the only cases this endpoint degrades gracefully for —
    // each one is a *transcription* gap the caller can reason about. Everything
    // that reaches this catch is a service fault: the download, ffprobe, the
    // ASS build, the ffmpeg burn, or the upload itself. Answering those with
    // `200 {subtitles: false}` plus an upload of the UN-SUBTITLED source wrote
    // a broken asset to the caller's final output_key and made a service fault
    // indistinguishable from a transcription gap. Fail loudly instead; the
    // caller decides whether to retry.
    res.status(500).json({ error: err.message });
  } finally {
    await cleanup(videoFile, assFile, audioTmp, outputFile);
  }
});

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
      ...CLEAN_META,
      "-y", outputFile,
    ]);

    const url = await uploadFile(outputFile, output_key, "video/mp4");
    const duration = await getDuration(outputFile);
    res.json({ url, duration, output_key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    await cleanup(videoFile, musicFile, outputFile);
  }
});

// --- POST /color-grade ---
// Apply a color-grade preset to a video (single re-encode). Audio is copied
// through untouched. Body: { video_url, output_key, grade }
// `grade` must be a known key in COLOR_GRADE_FILTERS ('none' is never sent —
// the Vercel caller skips this endpoint entirely for 'none').
// Response: { url, duration, output_key, grade }

app.post("/color-grade", auth, async (req, res) => {
  const { video_url, output_key, grade } = req.body;
  if (!video_url || !output_key || !grade) {
    return res.status(400).json({ error: "video_url, output_key, grade required" });
  }
  const keyErr = validateOutputKey(output_key);
  if (keyErr) return res.status(400).json({ error: keyErr });

  const vf = COLOR_GRADE_FILTERS[grade];
  if (!vf) {
    return res.status(400).json({
      error: `Unknown grade '${grade}'. Expected one of: ${Object.keys(COLOR_GRADE_FILTERS).join(", ")}`,
    });
  }

  const videoFile = tmpPath(".mp4");
  const outputFile = tmpPath(".mp4");

  try {
    await download(video_url, videoFile);

    await exec("ffmpeg", [
      "-y", "-i", videoFile,
      "-vf", vf,
      "-c:v", "libx264", "-profile:v", "baseline", "-level", "3.1",
      "-pix_fmt", "yuv420p", "-crf", "18", "-preset", "fast",
      "-c:a", "copy",
      ...CLEAN_META,
      outputFile,
    ]);

    const url = await uploadFile(outputFile, output_key, "video/mp4");
    const duration = await getDuration(outputFile);
    res.json({ url, duration, output_key, grade });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    await cleanup(videoFile, outputFile);
  }
});

// --- POST /atempo ---
// Apply a single-pass ffmpeg atempo filter to an audio file.
// Used by the Vercel-side bake pipeline to speed up VO that landed
// slightly longer than the merged video duration. We cap on the caller
// side at 1.25× (industry-standard transparent time-stretch ceiling);
// here we accept ffmpeg's natural single-pass range [0.5, 2.0] so this
// endpoint stays generic in case future callers need a wider band.
//
// Body: { audio_url, output_key, atempo }
// Response: { url, duration, output_key, applied_atempo }
app.post("/atempo", auth, async (req, res) => {
  const { audio_url, output_key, atempo } = req.body;
  if (!audio_url || !output_key || atempo === undefined) {
    return res.status(400).json({ error: "audio_url, output_key, atempo required" });
  }
  const keyErr = validateOutputKey(output_key);
  if (keyErr) return res.status(400).json({ error: keyErr });

  const factor = Number(atempo);
  if (!Number.isFinite(factor) || factor < 0.5 || factor > 2.0) {
    return res.status(400).json({ error: "atempo must be a number in [0.5, 2.0]" });
  }

  const audioFile = tmpPath(".mp3");
  const outputFile = tmpPath(".mp3");

  try {
    await download(audio_url, audioFile);
    await exec("ffmpeg", [
      "-y", "-i", audioFile,
      "-filter:a", `atempo=${factor.toFixed(4)}`,
      "-c:a", "libmp3lame",
      "-b:a", "128k",
      outputFile,
    ]);
    const url = await uploadFile(outputFile, output_key, "audio/mpeg");
    const duration = await getDuration(outputFile);
    res.json({ url, duration, output_key, applied_atempo: factor });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    await cleanup(audioFile, outputFile);
  }
});

// --- POST /extract-thumbnail ---
// Extract a single JPG frame at `timestamp_sec` (default 1s), upload to storage.
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

    const url = await uploadFile(thumbFile, output_key, "image/jpeg");
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
