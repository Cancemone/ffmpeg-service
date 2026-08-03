const test = require("node:test");
const assert = require("node:assert/strict");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const {
  TMP_MAX_AGE_MS,
  isServiceTmpName,
  sweepStaleTmpFiles,
  tmpPath,
} = require("../tmp-files");

test("tmpPath produces names the sweep recognises", () => {
  for (const ext of [".mp4", ".mp3", ".ass", ".img", ".jpg"]) {
    const name = path.basename(tmpPath(ext));
    assert.equal(isServiceTmpName(name), true, name);
  }
});

// The sweep runs against the shared /tmp, so the pattern has to be narrow
// enough that nothing else on the box is in scope.
test("isServiceTmpName only matches this service's own temp files", () => {
  for (const name of [
    "ff_0123456789ab.mp4",
    "ff_ffffffffffff.jpg",
  ]) {
    assert.equal(isServiceTmpName(name), true, name);
  }
  for (const name of [
    "ffmpeg-passlog.log",
    "ff_short.mp4",
    "ff_0123456789ab",
    "ff_0123456789ab.mp4.part",
    "ff_zzzzzzzzzzzz.mp4",
    "systemd-private-ff_0123456789ab.mp4",
    "important.mp4",
  ]) {
    assert.equal(isServiceTmpName(name), false, name);
  }
});

async function withTmpDir(fn) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "sweep-test-"));
  try {
    return await fn(dir);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
}

async function writeAged(dir, name, ageMs, now) {
  const full = path.join(dir, name);
  await fsp.writeFile(full, "x");
  const when = new Date(now - ageMs);
  await fsp.utimes(full, when, when);
  return full;
}

test("sweepStaleTmpFiles removes only our own leftovers past the age limit", async () => {
  await withTmpDir(async (dir) => {
    const now = Date.now();
    const stale = await writeAged(dir, "ff_0123456789ab.mp4", TMP_MAX_AGE_MS + 60_000, now);
    // A render in flight: ffmpeg is capped at 5 min, so anything this young may
    // still be an input file another invocation is reading.
    const live = await writeAged(dir, "ff_ba9876543210.mp3", 60_000, now);
    const foreign = await writeAged(dir, "someone-elses.mp4", TMP_MAX_AGE_MS * 10, now);

    const removed = await sweepStaleTmpFiles({ dir, now });

    assert.equal(removed, 1);
    assert.equal(await fsp.access(stale).then(() => true, () => false), false);
    assert.equal(await fsp.access(live).then(() => true, () => false), true);
    assert.equal(await fsp.access(foreign).then(() => true, () => false), true);
  });
});

test("sweepStaleTmpFiles skips directories that happen to match the pattern", async () => {
  await withTmpDir(async (dir) => {
    const now = Date.now();
    const nested = path.join(dir, "ff_0123456789ab.mp4");
    await fsp.mkdir(nested);
    const old = new Date(now - TMP_MAX_AGE_MS * 2);
    await fsp.utimes(nested, old, old);

    assert.equal(await sweepStaleTmpFiles({ dir, now }), 0);
    assert.equal(await fsp.access(nested).then(() => true, () => false), true);
  });
});

// Startup must never be blocked by a missing or unreadable temp dir.
test("sweepStaleTmpFiles resolves to 0 when the directory cannot be read", async () => {
  const missing = path.join(os.tmpdir(), "sweep-test-does-not-exist-12345");
  assert.equal(await sweepStaleTmpFiles({ dir: missing }), 0);
});
