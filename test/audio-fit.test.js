const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {
  overlayAudioOverflow,
  OVERLAY_MAX_OVERFLOW_SEC,
  MERGE_TRANSITION_SEC,
} = require("../audio-fit");

test("audio that fits inside the video is not an overflow", () => {
  assert.deepEqual(overlayAudioOverflow(9.5, 10), { overflowSec: -0.5, exceedsTolerance: false });
  assert.deepEqual(overlayAudioOverflow(10, 10), { overflowSec: 0, exceedsTolerance: false });
});

test("sub-tolerance overrun is left to the -t bound, not reported as a fault", () => {
  // The final ffmpeg call already caps the output at videoDur; a few tens of ms
  // of mp3-frame / ffprobe slop must not fail a paid run at its last step.
  assert.equal(overlayAudioOverflow(10.2, 10).exceedsTolerance, false);
  assert.equal(overlayAudioOverflow(10 + OVERLAY_MAX_OVERFLOW_SEC, 10).exceedsTolerance, false);
});

test("the band the old trim branch accepted is still accepted", () => {
  // Before this endpoint started failing, it trimmed only above 0.3s — and the
  // trim was a no-op, because the muxing call below it already carries
  // `-t videoDur`. So every overflow up to 0.3s produced a normal 200 with
  // byte-identical output. Narrowing the window would turn that known-good band
  // into a hard failure of a paid run at its last step, which is a strictly new
  // fault, not the one this guard was added for.
  assert.equal(overlayAudioOverflow(10.3, 10).exceedsTolerance, false);
});

test("the xfade budget the global VO used to ignore is over tolerance from the very first junction", () => {
  // /merge overlaps every junction, so an N-clip ad renders
  // MERGE_TRANSITION_SEC * (N - 1) shorter than the sum of its clip durations.
  // The Vercel bake used to fit the single global mp3 to that raw sum, and
  // /overlay cut the difference off the tail — where the CTA lives.
  for (const clips of [2, 3, 5]) {
    const videoDur = 30 - MERGE_TRANSITION_SEC * (clips - 1);
    const audioDur = 30; // VO fitted to the raw sum
    const r = overlayAudioOverflow(audioDur, videoDur);
    assert.equal(r.overflowSec, MERGE_TRANSITION_SEC * (clips - 1));
    assert.equal(r.exceedsTolerance, true, `${clips} clips should be reported`);
  }
});

test("overflow is rounded to ms so float noise never leaks into logs or the response", () => {
  assert.equal(overlayAudioOverflow(12.5, 12.2).overflowSec, 0.3);
});

test("MERGE_TRANSITION_SEC is pinned, and matched against creative-studio when it is checked out beside us", () => {
  // creative-studio/lib/creative/ffmpeg.ts owns this number; we duplicate the
  // literal because it is a separate repo with no importable module. Pinning it
  // here only makes a change on THIS side deliberate — on its own it cannot see
  // a change on the other side, which is the drift that actually breaks runs
  // (the VO is sized against a timeline /merge no longer produces).
  assert.equal(MERGE_TRANSITION_SEC, 0.4);

  // Best-effort real cross-repo check: in the two-repo dev layout the sibling
  // is right there, so read its constant and compare. Skipped where only this
  // repo is checked out (the VPS deploy), which is why the literal above stays.
  const sibling = path.join(__dirname, "..", "..", "creative-studio", "lib", "creative", "ffmpeg.ts");
  if (!fs.existsSync(sibling)) return;
  const src = fs.readFileSync(sibling, "utf8");
  const m = src.match(/export const MERGE_TRANSITION_SEC\s*=\s*([0-9.]+)/);
  assert.ok(m, "creative-studio no longer exports MERGE_TRANSITION_SEC — the duplication note is stale");
  assert.equal(Number(m[1]), MERGE_TRANSITION_SEC);
});
