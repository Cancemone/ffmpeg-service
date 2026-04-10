const express = require("express");
const { execFile } = require("child_process");
const { promisify } = require("util");
const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
} = require("@aws-sdk/client-s3");

const exec = promisify(execFile);
const app = express();
app.use(express.json());

const AUTH_TOKEN = process.env.AUTH_TOKEN;

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

async function download(url, dest) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Download failed: ${res.status} ${url}`);
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
  if (!AUTH_TOKEN) return next();
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

app.post("/merge", auth, async (req, res) => {
  const { clips, output_key, transition_duration } = req.body;
  if (!clips || !Array.isArray(clips) || clips.length < 1 || !output_key) {
    return res.status(400).json({ error: "clips[] and output_key required" });
  }

  const TRANSITION = transition_duration || 0.4;
  const clipFiles = clips.map(() => tmpPath(".mp4"));
  const normFiles = clips.map(() => tmpPath(".mp4"));
  const outputFile = tmpPath(".mp4");

  try {
    // Download all clips
    await Promise.all(clips.map((c, i) => download(c.url, clipFiles[i])));

    // Check if clips have audio
    const firstHasAudio = await hasAudioStream(clipFiles[0]);

    // Normalize all clips to 24fps (+ audio if present)
    const durations = [];
    for (let i = 0; i < clipFiles.length; i++) {
      const normArgs = ["-y", "-i", clipFiles[i], "-vf", "fps=24"];
      if (firstHasAudio) {
        normArgs.push("-af", "aresample=48000", "-c:v", "libx264", "-c:a", "aac");
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

        if (firstHasAudio) {
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

      if (firstHasAudio) {
        mergeArgs.push("-map", "[a]", "-c:a", "aac", "-ar", "44100");
      }

      mergeArgs.push(
        "-c:v", "libx264", "-profile:v", "baseline", "-level", "3.1",
        "-pix_fmt", "yuv420p", "-crf", "18", "-preset", "fast",
        outputFile,
      );

      await exec("ffmpeg", mergeArgs, { timeout: 120000 });
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

// --- POST /burn-subs ---
// Burn ASS subtitles into video

app.post("/burn-subs", auth, async (req, res) => {
  const { video_url, words, output_key, language } = req.body;

  if (!video_url || !output_key) {
    return res.status(400).json({ error: "video_url and output_key required" });
  }

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
        // No Whisper credentials — return video as-is
        const url = await uploadToR2(videoFile, output_key, "video/mp4");
        return res.json({ url, output_key, subtitles: false });
      }

      // Extract audio for Whisper
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

    // Build ASS subtitle file
    const chunks = [];
    for (let i = 0; i < wordList.length; i += 4) {
      const group = wordList.slice(i, i + 4);
      const text = group.map((w) => w.word).join(" ");
      chunks.push({ start: group[0].start, end: group[group.length - 1].end, text });
    }

    const outlineColor = "&H000066FF";
    let assContent = `[Script Info]
ScriptType: v4.00+
PlayResX: 720
PlayResY: 1280
ScaledBorderAndShadow: yes

[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
Style: Default,DejaVu Sans,42,&H00FFFFFF,&H000000FF,${outlineColor},&H00000000,1,0,0,0,100,100,0,0,1,2,0,2,10,10,140,1

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
`;

    for (const { start, end, text } of chunks) {
      assContent += `Dialogue: 0,${toAssTime(start)},${toAssTime(end)},Default,,0,0,0,,${text}\n`;
    }

    await fsp.writeFile(assFile, assContent, "utf-8");

    // Burn subtitles into video
    await exec("ffmpeg", [
      "-y",
      "-i", videoFile,
      "-vf", `ass=${assFile}`,
      "-c:v", "libx264", "-profile:v", "baseline", "-level", "3.1",
      "-pix_fmt", "yuv420p", "-crf", "18", "-preset", "fast",
      "-c:a", "copy",
      outputFile,
    ], { timeout: 120000 });

    const url = await uploadToR2(outputFile, output_key, "video/mp4");
    const duration = await getDuration(outputFile);

    res.json({ url, duration, output_key, subtitles: true, chunks: chunks.length });
  } catch (err) {
    // Fallback: upload video without subs
    try {
      const url = await uploadToR2(videoFile, output_key, "video/mp4");
      res.json({ url, output_key, subtitles: false, reason: err.message });
    } catch (uploadErr) {
      res.status(500).json({ error: err.message });
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

// --- Start ---

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`ffmpeg-service listening on :${PORT}`));
