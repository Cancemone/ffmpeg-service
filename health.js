"use strict";

// Health-check logic, kept out of server.js so it can be tested — server.js
// calls app.listen() and process.exit() at module scope and cannot be required.
//
// The old handler answered `{ status: "ok", ffmpeg: true }` from a literal, so
// it stayed green when the binaries were gone, when PATH under pm2 was wrong,
// and when the Supabase S3 credentials had been rotated. DEPLOY.md uses that
// response as proof the VPS works, and it is the obvious target for uptime
// monitoring — the one probe that must not lie.

// Parse the first line of `ffmpeg -version` / `ffprobe -version`:
//   "ffmpeg version 6.1.1-3ubuntu5 Copyright (c) 2000-2023 the FFmpeg developers"
// Returns null when the output does not look like a version banner at all,
// which is how a shim or a wrong binary on PATH shows up.
function parseVersion(stdout) {
  const first = String(stdout || "").split("\n")[0] || "";
  const m = first.match(/^(ffmpeg|ffprobe) version (\S+)/);
  return m ? m[2] : null;
}

// Decide the HTTP shape from the two probe outcomes. Pure, so the branch table
// is testable without spawning anything.
//
// A degraded box must answer 503: a monitor that only looks at the status code
// is the whole point, and a 200 with `"status": "degraded"` buried in the body
// is how an outage goes unnoticed for a day.
function healthResponse({ ffmpeg, ffprobe }) {
  const ok = Boolean(ffmpeg && ffprobe);
  return {
    status: ok ? 200 : 503,
    body: {
      status: ok ? "ok" : "degraded",
      ffmpeg: ffmpeg || null,
      ffprobe: ffprobe || null,
    },
  };
}

module.exports = { parseVersion, healthResponse };
