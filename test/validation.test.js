const test = require("node:test");
const assert = require("node:assert/strict");
const {
  validateOutputKey,
  isPrivateIp,
  parseHostPatterns,
  hostAllowed,
} = require("../validation");

test("validateOutputKey accepts the keys the app actually produces", () => {
  assert.equal(validateOutputKey("runs/2f8c/merged.mp4"), null);
  assert.equal(validateOutputKey("runs/2f8c/global-vo-fitted.mp3"), null);
  assert.equal(validateOutputKey("runs/2f8c/thumbnail.jpg"), null);
});

test("validateOutputKey rejects traversal, absolute paths and odd extensions", () => {
  assert.match(validateOutputKey("../etc/passwd.mp4"), /invalid shape/);
  assert.match(validateOutputKey("/runs/a.mp4"), /invalid shape/);
  assert.match(validateOutputKey("runs/a.exe"), /invalid shape/);
  assert.match(validateOutputKey(42), /must be a string/);
});

test("isPrivateIp blocks loopback, RFC1918, CGNAT and cloud metadata", () => {
  for (const addr of [
    "127.0.0.1",
    "10.0.0.5",
    "172.16.3.9",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "::1",
    "fd00::1",
    "::ffff:127.0.0.1",
    "not-an-ip",
  ]) {
    assert.equal(isPrivateIp(addr), true, `${addr} should be private`);
  }
});

test("isPrivateIp allows public addresses", () => {
  assert.equal(isPrivateIp("8.8.8.8"), false);
  assert.equal(isPrivateIp("2606:4700::1111"), false);
});

test("hostAllowed with an empty pattern list allows everything", () => {
  assert.equal(hostAllowed("example.com", []), true);
});

test("hostAllowed matches exact hosts and wildcard suffixes", () => {
  const patterns = parseHostPatterns("klolxchomofbfwwnmbdy.supabase.co, *.klingai.com");
  assert.equal(hostAllowed("klolxchomofbfwwnmbdy.supabase.co", patterns), true);
  assert.equal(hostAllowed("cdn.klingai.com", patterns), true);
  assert.equal(hostAllowed("klingai.com", patterns), true);
  assert.equal(hostAllowed("evil.example.com", patterns), false);
});
