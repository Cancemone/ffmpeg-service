"use strict";

// /health used to return a hardcoded `{ status: "ok", ffmpeg: true }`, which
// stayed green with the binaries missing, PATH broken under pm2, or the storage
// credentials rotated — while DEPLOY.md and any uptime monitor treat that
// response as proof the VPS works.

const { test } = require("node:test");
const assert = require("node:assert");
const { parseVersion, healthResponse } = require("../health");

test("parseVersion reads the version out of a real ffmpeg banner", () => {
  const banner =
    "ffmpeg version 6.1.1-3ubuntu5 Copyright (c) 2000-2023 the FFmpeg developers\n" +
    "built with gcc 13 (Ubuntu 13.2.0)";
  assert.strictEqual(parseVersion(banner), "6.1.1-3ubuntu5");
});

test("parseVersion reads ffprobe too", () => {
  assert.strictEqual(
    parseVersion("ffprobe version 7.0.2 Copyright (c) 2007-2024"),
    "7.0.2"
  );
});

test("parseVersion returns null for output that is not a version banner", () => {
  // A shim, a wrapper script, or the wrong binary earlier on PATH.
  for (const junk of ["", null, undefined, "not found", "bash: ffmpeg: command not found", "version 6.1.1"]) {
    assert.strictEqual(parseVersion(junk), null, JSON.stringify(junk));
  }
});

test("healthResponse is 200 only when BOTH binaries answered", () => {
  const res = healthResponse({ ffmpeg: "6.1.1", ffprobe: "6.1.1" });
  assert.strictEqual(res.status, 200);
  assert.deepStrictEqual(res.body, { status: "ok", ffmpeg: "6.1.1", ffprobe: "6.1.1" });
});

test("healthResponse is 503 when either binary is missing", () => {
  // 503 and not a 200 carrying "degraded": a monitor that only reads the status
  // code is exactly the caller this endpoint exists for.
  assert.strictEqual(healthResponse({ ffmpeg: "6.1.1", ffprobe: null }).status, 503);
  assert.strictEqual(healthResponse({ ffmpeg: null, ffprobe: "6.1.1" }).status, 503);
  assert.strictEqual(healthResponse({ ffmpeg: null, ffprobe: null }).status, 503);
});

test("healthResponse reports WHICH binary is missing", () => {
  const { body } = healthResponse({ ffmpeg: "6.1.1", ffprobe: null });
  assert.strictEqual(body.status, "degraded");
  assert.strictEqual(body.ffmpeg, "6.1.1");
  assert.strictEqual(body.ffprobe, null);
});
