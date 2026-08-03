// Parsing for ffprobe output. Pure — server.js runs the process, this decides
// what its stdout means, so the decision is unit-testable without ffprobe on
// the box.

// Reads `ffprobe -show_entries stream=codec_type -of csv=p=0`: one codec_type
// per line, one line per stream, in stream order.
//
// Deliberately NOT run with `-select_streams a`. The distinction that matters
// to /mix-background is "this clip is silent" vs "the probe told us nothing",
// and a selector that matches nothing collapses both into empty stdout — a
// silent /still-to-clip output, which is the ORDINARY /merge input, would be
// indistinguishable from a broken probe. Listing every stream means a readable
// media file always yields at least one line.
function parseStreamCodecTypes(stdout) {
  return String(stdout ?? "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

// null = the probe produced nothing, which is never a real answer for a file
// ffmpeg is about to read. The caller must escalate rather than guess: guessing
// `false` here shipped ads with the voiceover silently dropped, under a 200.
function audioPresenceFromCodecTypes(types) {
  if (!types || types.length === 0) return null;
  return types.includes("audio");
}

module.exports = { parseStreamCodecTypes, audioPresenceFromCodecTypes };
