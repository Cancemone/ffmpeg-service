// End-to-end smoke test against a DEPLOYED ffmpeg-service.
//
// Generates synthetic media locally (ffmpeg lavfi sources), uploads it to the
// same bucket the service writes to, then drives every endpoint and asserts
// the returned URL is publicly fetchable. No generation-provider credits are
// spent — this validates transport, auth, ffmpeg and storage only.
//
// Usage (from the repo root, with .env loaded):
//   SERVICE_URL=https://ffmpeg.example.com node scripts/smoke.mjs
//
// SERVICE_URL defaults to http://127.0.0.1:3000 so it can also be run on the
// VPS itself, bypassing nginx.

import "dotenv/config";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { uploadFile, deleteFile } = require("../storage.js");

const exec = promisify(execFile);
const SERVICE_URL = (process.env.SERVICE_URL || "http://127.0.0.1:3000").replace(/\/+$/, "");
const TOKEN = process.env.AUTH_TOKEN;
if (!TOKEN) {
  console.error("AUTH_TOKEN is required (load the service .env)");
  process.exit(1);
}

const RUN_ID = `smoke-${Date.now()}`;
const prefix = `runs/${RUN_ID}`;
const created = [];

function key(name) {
  const k = `${prefix}/${name}`;
  created.push(k);
  return k;
}

async function call(path, body) {
  const res = await fetch(`${SERVICE_URL}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${TOKEN}`,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(600_000),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${path} → ${res.status}: ${text.slice(0, 300)}`);
  return JSON.parse(text);
}

async function assertFetchable(url) {
  const res = await fetch(url, { method: "GET", signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`output not publicly readable: ${url} → ${res.status}`);
  const bytes = (await res.arrayBuffer()).byteLength;
  if (bytes < 1000) throw new Error(`output suspiciously small (${bytes} bytes): ${url}`);
}

const results = [];
async function step(name, fn) {
  const startedAt = Date.now();
  const out = await fn();
  results.push(`PASS  ${name}  (${Date.now() - startedAt}ms)`);
  return out;
}

const dir = await mkdtemp(join(tmpdir(), "smoke-"));

try {
  // ─── Fixtures: two 3s colour bars clips, one 2s tone, one still ─────────
  const clipA = join(dir, "a.mp4");
  const clipB = join(dir, "b.mp4");
  const tone = join(dir, "tone.mp3");
  const still = join(dir, "still.png");
  const music = join(dir, "music.mp3");

  await exec("ffmpeg", ["-y", "-f", "lavfi", "-i", "testsrc=size=720x1280:rate=24:duration=3",
    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-an", clipA]);
  await exec("ffmpeg", ["-y", "-f", "lavfi", "-i", "smptebars=size=720x1280:rate=24:duration=3",
    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-an", clipB]);
  await exec("ffmpeg", ["-y", "-f", "lavfi", "-i", "sine=frequency=440:duration=2",
    "-c:a", "libmp3lame", "-b:a", "128k", tone]);
  await exec("ffmpeg", ["-y", "-f", "lavfi", "-i", "sine=frequency=220:duration=6",
    "-c:a", "libmp3lame", "-b:a", "128k", music]);
  await exec("ffmpeg", ["-y", "-f", "lavfi", "-i", "color=c=blue:size=720x1280",
    "-frames:v", "1", still]);

  const clipAUrl = await uploadFile(clipA, key("in-a.mp4"), "video/mp4");
  const clipBUrl = await uploadFile(clipB, key("in-b.mp4"), "video/mp4");
  const toneUrl = await uploadFile(tone, key("in-tone.mp3"), "audio/mpeg");
  const musicUrl = await uploadFile(music, key("in-music.mp3"), "audio/mpeg");
  const stillUrl = await uploadFile(still, key("in-still.png"), "image/png");
  results.push("PASS  storage upload (5 fixtures)");

  // ─── /still-to-clip ─────────────────────────────────────────────────────
  const stillClip = await step("/still-to-clip", async () => {
    const r = await call("/still-to-clip", {
      image_url: stillUrl, duration_sec: 2, output_key: key("still.mp4"),
    });
    await assertFetchable(r.url);
    return r;
  });

  // ─── /overlay ───────────────────────────────────────────────────────────
  const overlaid = await step("/overlay", async () => {
    const r = await call("/overlay", {
      video_url: clipAUrl, audio_url: toneUrl, output_key: key("overlaid.mp4"),
    });
    await assertFetchable(r.url);
    return r;
  });

  // ─── /merge (mixed audio/silent inputs, the real-world case) ────────────
  const merged = await step("/merge", async () => {
    const r = await call("/merge", {
      clips: [{ url: overlaid.url }, { url: clipBUrl }, { url: stillClip.url }],
      output_key: key("merged.mp4"),
      transition_duration: 0.4,
      width: 720,
      height: 1280,
    });
    await assertFetchable(r.url);
    return r;
  });

  // ─── /mix-background ────────────────────────────────────────────────────
  const mixed = await step("/mix-background", async () => {
    const r = await call("/mix-background", {
      video_url: merged.url, music_url: musicUrl, output_key: key("bgm.mp4"),
    });
    await assertFetchable(r.url);
    return r;
  });

  // ─── /color-grade ───────────────────────────────────────────────────────
  const graded = await step("/color-grade", async () => {
    const r = await call("/color-grade", {
      video_url: mixed.url, output_key: key("graded.mp4"), grade: "punchy",
    });
    await assertFetchable(r.url);
    return r;
  });

  // ─── /burn-subs with explicit words (no Whisper needed) ─────────────────
  await step("/burn-subs", async () => {
    const r = await call("/burn-subs", {
      video_url: graded.url,
      output_key: key("subs.mp4"),
      style: "bold_outline",
      language: "en",
      words: [
        { word: "smoke", start: 0.2, end: 0.8 },
        { word: "test", start: 0.8, end: 1.4 },
        { word: "passed", start: 1.4, end: 2.2 },
      ],
    });
    if (!r.subtitles) throw new Error(`subtitles not burned: ${r.reason}`);
    await assertFetchable(r.url);
    return r;
  });

  // ─── /extract-audio ─────────────────────────────────────────────────────
  await step("/extract-audio", async () => {
    const r = await call("/extract-audio", {
      video_url: graded.url, output_key: key("audio.mp3"),
    });
    await assertFetchable(r.url);
    return r;
  });

  // ─── /extract-thumbnail ─────────────────────────────────────────────────
  await step("/extract-thumbnail", async () => {
    const r = await call("/extract-thumbnail", {
      video_url: graded.url, output_key: key("thumb.jpg"), timestamp_sec: 1,
    });
    if (!r.width || !r.height) throw new Error("thumbnail returned no dimensions");
    await assertFetchable(r.url);
    return r;
  });

  // ─── /atempo ────────────────────────────────────────────────────────────
  await step("/atempo", async () => {
    const r = await call("/atempo", {
      audio_url: toneUrl, output_key: key("tone-fast.mp3"), atempo: 1.15,
    });
    if (Math.abs(r.applied_atempo - 1.15) > 0.001) {
      throw new Error(`applied_atempo mismatch: ${r.applied_atempo}`);
    }
    await assertFetchable(r.url);
    return r;
  });

  console.log(results.join("\n"));
  console.log(`\nAll endpoints OK. Artifacts under ${prefix}/`);
} finally {
  await rm(dir, { recursive: true, force: true });
  for (const k of created) {
    await deleteFile(k).catch(() => {});
  }
}
