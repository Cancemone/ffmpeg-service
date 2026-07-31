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

module.exports = {
  OUTPUT_KEY_RE,
  validateOutputKey,
  isPrivateIp,
  parseHostPatterns,
  hostAllowed,
};
