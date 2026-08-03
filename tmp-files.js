// Scratch files for the ffmpeg pipeline, and the startup sweep that collects
// the ones a previous process never got to delete.
//
// Every endpoint unlinks its own files in `finally`, but that block does not
// run when the process dies mid-request — an OOM kill, a `pm2 restart` during
// a 30-clip merge, a SIGKILLed ffmpeg taking the box down with it. Those
// leftovers used to sit in /tmp until the distro's own tmp cleaner (if any)
// noticed them.

const fsp = require("fs").promises;
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const TMP_PREFIX = "ff_";

// Only files older than this are swept.
//
// An hour does NOT bound how long a live file can sit untouched: /merge
// downloads all N clips up front and only reads clipFiles[i] at normalisation
// step i, so with MAX_CLIPS_PER_MERGE the last file's untouched window is up to
// (N-1) x FFMPEG_TIMEOUT_MS, which crosses an hour. What actually makes this
// safe is that the sweep runs ONCE at startup and the documented deployment
// (DEPLOY.md: `pm2 start` fork mode + `pm2 restart`) has no second process —
// the old one is dead before the new one sweeps, so there is no in-flight
// request whose files this could delete. Run two instances against the same
// /tmp and that stops being true; the sweep would need a liveness marker, not
// a bigger number.
const TMP_MAX_AGE_MS = 60 * 60 * 1000;

// Exactly what tmpPath() produces: prefix, 12 hex chars, one extension. The
// sweep runs against the shared /tmp, so this must not match anything a
// different program could have put there.
const TMP_NAME_RE = /^ff_[0-9a-f]{12}\.[a-z0-9]+$/;

function tmpPath(ext) {
  return path.join(os.tmpdir(), `${TMP_PREFIX}${crypto.randomBytes(6).toString("hex")}${ext}`);
}

function isServiceTmpName(name) {
  return TMP_NAME_RE.test(name);
}

// Returns how many files were removed. Never rejects: this runs at startup and
// a sweep that cannot read /tmp is not a reason to refuse to serve.
async function sweepStaleTmpFiles({ dir = os.tmpdir(), maxAgeMs = TMP_MAX_AGE_MS, now = Date.now() } = {}) {
  let names;
  try {
    names = await fsp.readdir(dir);
  } catch {
    return 0;
  }
  let removed = 0;
  for (const name of names) {
    if (!isServiceTmpName(name)) continue;
    const full = path.join(dir, name);
    try {
      const stat = await fsp.stat(full);
      // mtime, not birthtime: a long download keeps writing, and judging it by
      // creation time could delete a file still being filled.
      if (!stat.isFile() || now - stat.mtimeMs < maxAgeMs) continue;
      await fsp.unlink(full);
      removed++;
    } catch {
      // Raced with another sweep or with a running render — leave it.
    }
  }
  return removed;
}

module.exports = { TMP_PREFIX, TMP_MAX_AGE_MS, tmpPath, isServiceTmpName, sweepStaleTmpFiles };
