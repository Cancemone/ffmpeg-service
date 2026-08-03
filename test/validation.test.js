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

// The bucket is shared with the app: personas, music and previously published
// creatives live next to run artifacts, and PutObject overwrites in place.
test("validateOutputKey rejects keys outside runs/<run-id>/", () => {
  assert.match(validateOutputKey("personas/x.jpg"), /invalid shape/);
  assert.match(validateOutputKey("music/track.mp3"), /invalid shape/);
  assert.match(validateOutputKey("kie-input/a.png"), /invalid shape/);
  assert.match(validateOutputKey("merged.mp4"), /invalid shape/);
  assert.match(validateOutputKey("runs/merged.mp4"), /invalid shape/);
  // No extra path segments: the run folder is flat.
  assert.match(validateOutputKey("runs/2f8c/nested/merged.mp4"), /invalid shape/);
  // A run id may not carry the separator itself.
  assert.match(validateOutputKey("runs/../music/track.mp3"), /invalid shape/);
});

test("validateOutputKey still rejects '..' inside an otherwise valid filename", () => {
  assert.match(validateOutputKey("runs/2f8c/a..b.mp4"), /'\.\.'/);
});

test("validateOutputKey accepts every filename shape the pipeline builds", () => {
  for (const key of [
    "runs/0f2a6c1e-8b7d-4a55-9c31-5b6e7d8f9a01/merged-vo.mp4",
    "runs/0f2a6c1e-8b7d-4a55-9c31-5b6e7d8f9a01/video-video_lz3k2b_7-vo.mp4",
    "runs/0f2a6c1e-8b7d-4a55-9c31-5b6e7d8f9a01/tts-image_clip_lz3k2b_2.mp3",
    "runs/0f2a6c1e-8b7d-4a55-9c31-5b6e7d8f9a01/global-vo-short-fitted.mp3",
    "runs/smoke-1754179200000/thumb.jpg",
  ]) {
    assert.equal(validateOutputKey(key), null, `${key} should be accepted`);
  }
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

// fe80::/10 is fe80 through febf — the whole nibble range, not just the two
// prefixes that were hardcoded. With an empty ALLOWED_DOWNLOAD_HOSTS (what
// DEPLOY.md tells operators to run) this function is the only SSRF control.
test("isPrivateIp blocks the whole fe80::/10 link-local range", () => {
  for (const addr of [
    "fe80::1",
    "fe90::1",
    "fea0::1",
    "feb0::1",
    "febf:ffff::1",
    "FEA0::1",
  ]) {
    assert.equal(isPrivateIp(addr), true, `${addr} should be private`);
  }
});

// A NAT64 address is an IPv4 destination wearing an IPv6 costume; judging the
// literal alone called the cloud-metadata address public.
test("isPrivateIp judges NAT64 addresses by the IPv4 they embed", () => {
  assert.equal(isPrivateIp("64:ff9b::a9fe:a9fe"), true); // 169.254.169.254
  assert.equal(isPrivateIp("64:ff9b::7f00:1"), true); // 127.0.0.1
  assert.equal(isPrivateIp("64:ff9b::169.254.169.254"), true);
  assert.equal(isPrivateIp("64:ff9b::808:808"), false); // 8.8.8.8
  assert.equal(isPrivateIp("64:ff9b::8.8.8.8"), false);
  // Undecodable tail — fail closed, like every other unparseable address here.
  assert.equal(isPrivateIp("64:ff9b::1"), true);
});

// The same address has several legal spellings. A textual `startsWith` check
// only ever recognised the canonical one, so the cloud-metadata address read
// as PUBLIC when written any other way — and "dns.lookup returns the canonical
// form" is a property of one caller, not of this function.
test("isPrivateIp recognises NAT64 in every legal spelling", () => {
  for (const addr of [
    "64:ff9b::a9fe:a9fe",
    "64:ff9b:0:0:0:0:a9fe:a9fe",
    "0064:ff9b::a9fe:a9fe",
    "0064:0ff9b:0:0:0:0:a9fe:a9fe".replace("0ff9b", "ff9b"),
    "64:FF9B::A9FE:A9FE",
  ]) {
    assert.equal(isPrivateIp(addr), true, `${addr} should be private`);
  }
  // Still not over-blocking the prefix: a public IPv4 behind the translator
  // must stay reachable, or a DNS64 network can download nothing.
  assert.equal(isPrivateIp("64:ff9b:0:0:0:0:808:808"), false);
});

test("isPrivateIp reads link-local and ULA as bit ranges, not text prefixes", () => {
  // Uncompressed and zero-padded forms of fe80::/10 and fc00::/7.
  assert.equal(isPrivateIp("fe80:0000:0000:0000:0000:0000:0000:0001"), true);
  assert.equal(isPrivateIp("fd12:3456::1"), true);
  assert.equal(isPrivateIp("fc00::1"), true);
  // `fe8::1` is 0fe8:: — three hex digits in the first group, nowhere near
  // fe80::/10. `/^fe[89ab]/` on the raw text called it link-local.
  assert.equal(isPrivateIp("fe8::1"), false);
  assert.equal(isPrivateIp("feb::1"), false);
});

test("isPrivateIp reads IPv4-mapped addresses in both spellings", () => {
  assert.equal(isPrivateIp("::ffff:169.254.169.254"), true);
  assert.equal(isPrivateIp("::ffff:a9fe:a9fe"), true);
  assert.equal(isPrivateIp("0:0:0:0:0:ffff:8.8.8.8"), false);
});

test("isPrivateIp fails closed on IPv6 text it cannot parse", () => {
  // net.isIP rejects these before the parser sees them; the point is that no
  // input reaches the `return false` at the bottom without being understood.
  for (const addr of ["fe80:::1", "1:2:3:4:5:6:7:8:9", "gggg::1", ""]) {
    assert.equal(isPrivateIp(addr), true, `${addr} should fail closed`);
  }
});

test("isPrivateIp allows public addresses", () => {
  assert.equal(isPrivateIp("8.8.8.8"), false);
  assert.equal(isPrivateIp("2606:4700::1111"), false);
  // fec0::/10 (site-local) was deprecated by RFC 3879 and is outside fe80::/10
  // — the nibble test must not swallow it by accident.
  assert.equal(isPrivateIp("fec0::1"), false);
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

const { parseDimensions, scaleAndPadFilter } = require("../validation");

test("parseDimensions defaults to 720x1280 when the caller sends nothing", () => {
  assert.deepEqual(parseDimensions({}), { width: 720, height: 1280 });
});

test("parseDimensions accepts explicit even dimensions in range", () => {
  assert.deepEqual(parseDimensions({ width: 1080, height: 1080 }), { width: 1080, height: 1080 });
  assert.deepEqual(parseDimensions({ width: 1280, height: 720 }), { width: 1280, height: 720 });
});

test("parseDimensions rejects odd, out-of-range and non-numeric values", () => {
  assert.match(parseDimensions({ width: 721, height: 1280 }).error, /even/);
  assert.match(parseDimensions({ width: 100, height: 1280 }).error, /between/);
  assert.match(parseDimensions({ width: 4000, height: 1280 }).error, /between/);
  assert.match(parseDimensions({ width: "wide", height: 1280 }).error, /number/);
});

test("parseDimensions requires both values or neither", () => {
  assert.match(parseDimensions({ width: 1080 }).error, /both/);
});

const { parseTransitionDuration, MAX_TRANSITION_SEC } = require("../validation");
const { MERGE_TRANSITION_SEC } = require("../audio-fit");

test("parseTransitionDuration defaults to the merge transition when unsent", () => {
  assert.deepEqual(parseTransitionDuration(undefined), { transition: MERGE_TRANSITION_SEC });
  assert.deepEqual(parseTransitionDuration(null), { transition: MERGE_TRANSITION_SEC });
});

test("parseTransitionDuration keeps an explicit 0 instead of defaulting", () => {
  // `transition_duration || MERGE_TRANSITION_SEC` silently turned a requested
  // hard cut back into a 0.4s cross-fade.
  assert.deepEqual(parseTransitionDuration(0), { transition: 0 });
});

test("parseTransitionDuration accepts values inside the xfade range", () => {
  assert.deepEqual(parseTransitionDuration(0.4), { transition: 0.4 });
  assert.deepEqual(parseTransitionDuration(MAX_TRANSITION_SEC), { transition: MAX_TRANSITION_SEC });
});

test("parseTransitionDuration rejects anything that would poison the filtergraph", () => {
  for (const bad of ["0.4:enable", "abc", NaN, Infinity, -1, 2.5, {}, [1, 2]]) {
    const out = parseTransitionDuration(bad);
    assert.match(out.error, /transition_duration/, `${JSON.stringify(bad)} should be rejected`);
    assert.equal(out.transition, undefined);
  }
});

test("scaleAndPadFilter builds the canonical normalisation chain", () => {
  assert.equal(
    scaleAndPadFilter(720, 1280),
    "scale=720:1280:force_original_aspect_ratio=decrease," +
      "pad=720:1280:(ow-iw)/2:(oh-ih)/2:black," +
      "setsar=1,format=yuv420p,fps=24",
  );
});
