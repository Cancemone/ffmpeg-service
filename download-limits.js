// Bounds on what `download()` is allowed to pull in, how many pulls run at
// once, and the disk write that enforces the first of those. No network and no
// env reads — server.js owns fetch and the SSRF checks — so `node --test` can
// reach all of it (same reason validation.js and audio-fit.js live outside
// server.js, which cannot be required at all).

const fs = require("fs");
const { Readable } = require("stream");
const { pipeline } = require("stream/promises");

// Ceiling on a single downloaded body.
//
// The body is streamed to disk, so this is a runaway guard, not a RAM budget:
// it stops a mistyped or provider-mangled URL from filling /tmp on the VPS.
// The largest legitimate body is the merged master an endpoint like /burn-subs
// re-downloads — a real ad is tens of MB, and even the absurd ceiling case
// (MAX_CLIPS_PER_MERGE × 15s at CRF 18) lands well under this.
const MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024;

// How many clips /merge downloads at once. `Promise.all` over all 30 URLs was
// the shape that made peak usage the sum of every body; with a small window
// the peak is bounded no matter how long the clip list is. Not a throughput
// knob — the normalisation pass right after it is sequential anyway.
const MERGE_DOWNLOAD_CONCURRENCY = 4;

// Cheap early-out before a single byte is read. An absent, empty or
// unparseable header answers "unknown", NOT "too large": chunked and gzipped
// responses legitimately have none, and the byte counter wrapped around the
// stream is the guard that actually enforces the cap.
function declaredTooLarge(headerValue, max = MAX_DOWNLOAD_BYTES) {
  if (headerValue === null || headerValue === undefined) return false;
  const text = String(headerValue).trim();
  if (text === "" || !/^\d+$/.test(text)) return false;
  const declared = Number(text);
  return Number.isFinite(declared) && declared > max;
}

// Promise.all with a window. Semantics that matter to the callers:
//   - results keep input order;
//   - the first failure stops new work from being scheduled...
//   - ...but tasks already in flight are awaited before the rejection
//     surfaces, because every endpoint unlinks its temp files in `finally` and
//     a still-writing download would race that cleanup into orphaned files.
async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  const errors = new Array(items.length);
  let nextIndex = 0;
  let failed = false;

  const workerCount = Math.max(1, Math.min(limit, items.length));
  await Promise.all(
    Array.from({ length: workerCount }, async () => {
      while (!failed) {
        const i = nextIndex++;
        if (i >= items.length) return;
        try {
          results[i] = await fn(items[i], i);
        } catch (err) {
          failed = true;
          errors[i] = err;
        }
      }
    }),
  );

  const firstError = errors.find((err) => err !== undefined);
  if (firstError) throw firstError;
  return results;
}

// Writes a fetch response body (a web ReadableStream) to `dest`, counting
// bytes as they pass and aborting the moment the total exceeds `max`. Returns
// the number of bytes written.
//
// `res.arrayBuffer()` held the entire body in RAM before anything touched
// disk, which is what made a large — or simply unbounded — response an
// out-of-memory risk for the whole process rather than a failed request.
// Counting here, mid-stream, is also the only enforcement that works when the
// response is chunked and declares no Content-Length.
async function streamToFile(body, dest, max = MAX_DOWNLOAD_BYTES) {
  let received = 0;
  await pipeline(
    Readable.fromWeb(body),
    async function* countBytes(source) {
      for await (const chunk of source) {
        received += chunk.length;
        if (received > max) throw new Error(`body exceeds the ${max}-byte cap`);
        yield chunk;
      }
    },
    fs.createWriteStream(dest),
  );
  return received;
}

module.exports = {
  MAX_DOWNLOAD_BYTES,
  MERGE_DOWNLOAD_CONCURRENCY,
  declaredTooLarge,
  mapWithConcurrency,
  streamToFile,
};
