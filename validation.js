// Pure request validators. No I/O, no env reads — everything is passed in so
// the whole module is unit-testable and server.js stays a thin HTTP shell.

// `output_key` is caller-influenced and used verbatim as an object key, in a
// bucket the app shares with personas, music and already-published creatives —
// and PutObject overwrites in place. So the pattern is anchored on the only
// thing this service ever writes: one flat file inside one run's folder,
// `runs/<run-id>/<name>.<ext>`. The previous pattern checked the first
// character, the character set and the extension but never the prefix it
// claimed to check, so `personas/x.jpg` and `music/track.mp3` passed.
//
// Segment 2 is the run id (uuid, or `smoke-<ts>` from scripts/smoke.mjs);
// segment 3 is a generated filename that embeds a graph node id
// (`video-video_lz3k2b_7-vo.mp4`), hence `_` and `-` but no `/`.
const OUTPUT_KEY_RE =
  /^runs\/[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\/[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}\.(mp4|mp3|jpg|jpeg|png|webp)$/;

function validateOutputKey(key) {
  if (typeof key !== "string") return "output_key must be a string";
  if (!OUTPUT_KEY_RE.test(key)) return "output_key has invalid shape";
  // Not redundant with the regex: dots are legal inside the filename segment,
  // so `runs/<id>/a..b.mp4` matches. A leading `/` no longer needs its own
  // check — the pattern is anchored on `runs/`.
  if (key.includes("..")) return "output_key must not contain '..'";
  return null;
}

const net = require("net");
const { MERGE_TRANSITION_SEC } = require("./audio-fit");

// SSRF safety net: every address a download URL resolves to must be public.
// An invalid address string counts as private (fail closed).
function isPrivateIp(addr) {
  const family = net.isIP(addr);
  if (family === 0) return true;
  if (family === 4) {
    const [a, b] = addr.split(".").map((n) => parseInt(n, 10));
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local incl. cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast + reserved
    return false;
  }
  const lower = addr.toLowerCase();
  if (lower === "::1" || lower === "::") return true;
  // Decide on the NUMBERS, not the text. The same address has several legal
  // spellings (`64:ff9b::a9fe:a9fe`, `0064:ff9b::a9fe:a9fe`,
  // `64:ff9b:0:0:0:0:a9fe:a9fe`), and a startsWith/regex check only ever sees
  // one of them — the others read as public. dns.lookup happens to return the
  // canonical form today, which is the only reason that was not already a hole.
  const words = expandIpv6(lower);
  if (words === null) return true; // unparseable → fail closed
  // Link-local fe80::/10: the top ten bits are 1111111010, so the first group
  // runs fe80 through febf. `/^fe[89ab]/` on the raw text also swallowed
  // `fe8::1`, which is 0fe8:: and not link-local at all.
  if ((words[0] & 0xffc0) === 0xfe80) return true;
  // ULA fc00::/7.
  if ((words[0] & 0xfe00) === 0xfc00) return true;
  // IPv4-mapped ::ffff:0:0/96 — judged by the IPv4 it carries.
  if (words.slice(0, 5).every((w) => w === 0) && words[5] === 0xffff) {
    return isPrivateIp(ipv4FromWords(words[6], words[7]));
  }
  // NAT64, RFC 6052 well-known prefix 64:ff9b::/96: the address is an IPv4
  // destination reached through a translator, so the embedded IPv4 is what
  // decides. `64:ff9b::a9fe:a9fe` is the cloud-metadata address. Blanket-
  // rejecting the prefix is not an option — on a DNS64 network every hostname
  // resolves into it, and this service would refuse every download.
  if (
    words[0] === 0x64 && words[1] === 0xff9b &&
    words[2] === 0 && words[3] === 0 && words[4] === 0 && words[5] === 0
  ) {
    return isPrivateIp(ipv4FromWords(words[6], words[7]));
  }
  return false;
}

function ipv4FromWords(hi, lo) {
  return [hi >> 8, hi & 0xff, lo >> 8, lo & 0xff].join(".");
}

// Expand any textual IPv6 into its eight 16-bit words. Returns null for
// anything that does not parse, so every caller fails closed. Handles `::`
// compression and the dotted-quad tail (`64:ff9b::169.254.169.254`).
function expandIpv6(addr) {
  let text = addr;
  // Dotted-quad tail → two hex groups, so the rest of the parser sees one shape.
  const dotted = text.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dotted) {
    if (net.isIP(dotted[1]) !== 4) return null;
    const o = dotted[1].split(".").map(Number);
    text = text.slice(0, dotted.index) +
      ((o[0] << 8) | o[1]).toString(16) + ":" + ((o[2] << 8) | o[3]).toString(16);
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const parse = (part) =>
    part === "" ? [] : part.split(":").map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  const head = parse(halves[0]);
  const tail = halves.length === 2 ? parse(halves[1]) : [];
  if ([...head, ...tail].some((w) => Number.isNaN(w))) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  const fill = 8 - head.length - tail.length;
  if (fill < 1) return null;
  return [...head, ...new Array(fill).fill(0), ...tail];
}

function parseHostPatterns(raw) {
  return (raw || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

// Empty pattern list = allow any public hostname; isPrivateIp remains the
// safety net. See README for why the list is deliberately left empty in
// production (Kling / kie CDN hostnames are provider-controlled and change).
function hostAllowed(hostname, patterns) {
  if (!patterns || patterns.length === 0) return true;
  const h = hostname.toLowerCase();
  for (const pattern of patterns) {
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(1); // ".example.com"
      if (h === suffix.slice(1) || h.endsWith(suffix)) return true;
    } else if (h === pattern) {
      return true;
    }
  }
  return false;
}

// Output geometry. Defaults preserve the pre-format behaviour (9:16 at
// 720x1280) for any caller that does not send dimensions yet.
const DEFAULT_WIDTH = 720;
const DEFAULT_HEIGHT = 1280;
const MIN_DIMENSION = 256;
const MAX_DIMENSION = 2160;

function parseDimensions(body) {
  const { width, height } = body || {};
  if (width === undefined && height === undefined) {
    return { width: DEFAULT_WIDTH, height: DEFAULT_HEIGHT };
  }
  if (width === undefined || height === undefined) {
    return { error: "width and height must be sent both or neither" };
  }
  for (const [name, value] of [["width", width], ["height", height]]) {
    if (typeof value !== "number" || !Number.isFinite(value)) {
      return { error: `${name} must be a number` };
    }
    if (!Number.isInteger(value) || value % 2 !== 0) {
      return { error: `${name} must be an even integer (libx264 yuv420p requirement)` };
    }
    if (value < MIN_DIMENSION || value > MAX_DIMENSION) {
      return { error: `${name} must be between ${MIN_DIMENSION} and ${MAX_DIMENSION}` };
    }
  }
  return { width, height };
}

// Cross-fade length for /merge. It was the one request field that reached the
// filtergraph unchecked, and it reaches it twice: as `xfade=duration=` and as
// the offset of every junction.
//
// Ceiling: xfade OVERLAPS neighbouring clips, so a transition longer than a
// clip drives the offset recurrence negative and ffmpeg aborts at init. 2s is
// well clear of that for the 2-15s clips this pipeline merges — the only real
// caller sends the 0.4 literal.
const MAX_TRANSITION_SEC = 2;

function parseTransitionDuration(value) {
  // `undefined || default` used to be the whole check, which also meant an
  // explicit 0 (hard cut) came back as 0.4.
  if (value === undefined || value === null) return { transition: MERGE_TRANSITION_SEC };
  const seconds = typeof value === "number" || typeof value === "string" ? Number(value) : NaN;
  if (!Number.isFinite(seconds) || seconds < 0 || seconds > MAX_TRANSITION_SEC) {
    return {
      error: `transition_duration must be a number between 0 and ${MAX_TRANSITION_SEC}`,
    };
  }
  return { transition: seconds };
}

// Canonical geometry normalisation. xfade aborts at init if any of
// (width, height, pixel format, SAR, timebase) differ between its two inputs,
// and Kling outputs disagree with /still-to-clip outputs on SAR / pix_fmt even
// at identical resolutions — so every clip goes through this exact chain.
function scaleAndPadFilter(width, height) {
  return (
    `scale=${width}:${height}:force_original_aspect_ratio=decrease,` +
    `pad=${width}:${height}:(ow-iw)/2:(oh-ih)/2:black,` +
    "setsar=1,format=yuv420p,fps=24"
  );
}

module.exports = {
  OUTPUT_KEY_RE,
  validateOutputKey,
  isPrivateIp,
  parseHostPatterns,
  hostAllowed,
  parseDimensions,
  parseTransitionDuration,
  scaleAndPadFilter,
  DEFAULT_WIDTH,
  DEFAULT_HEIGHT,
  MAX_TRANSITION_SEC,
};
