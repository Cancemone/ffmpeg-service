// Pure request validators. No I/O, no env reads — everything is passed in so
// the whole module is unit-testable and server.js stays a thin HTTP shell.

// `output_key` is caller-influenced and used verbatim as an object key.
// Without validation a caller could overwrite any existing object (e.g. an
// already-published creative). Force a predictable shape: known prefixes,
// known extensions, no traversal.
const OUTPUT_KEY_RE =
  /^[a-zA-Z0-9][a-zA-Z0-9/_.\-]{0,199}\.(mp4|mp3|jpg|jpeg|png|webp)$/;

function validateOutputKey(key) {
  if (typeof key !== "string") return "output_key must be a string";
  if (!OUTPUT_KEY_RE.test(key)) return "output_key has invalid shape";
  if (key.includes("..")) return "output_key must not contain '..'";
  if (key.startsWith("/")) return "output_key must not start with '/'";
  return null;
}

const net = require("net");

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
  if (lower.startsWith("fe80:") || lower.startsWith("fe90:")) return true;
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // ULA
  if (lower.startsWith("::ffff:")) return isPrivateIp(lower.slice("::ffff:".length));
  return false;
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
  scaleAndPadFilter,
  DEFAULT_WIDTH,
  DEFAULT_HEIGHT,
};
