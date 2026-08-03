const test = require("node:test");
const assert = require("node:assert");
const { parseStreamCodecTypes, audioPresenceFromCodecTypes } = require("../probe");

// /mix-background branches on this: "the clip already has a voiceover" mixes,
// "it is silent" takes the music-only path. Getting it wrong ships an ad with
// the voiceover dropped, under a 200. Before the fix the branch swallowed a
// FAILED probe as `false`, which is the same wrong answer with no trace.

test("parseStreamCodecTypes reads one codec_type per stream", () => {
  assert.deepEqual(parseStreamCodecTypes("video\naudio\n"), ["video", "audio"]);
  assert.deepEqual(parseStreamCodecTypes("video\r\naudio\r\n"), ["video", "audio"]);
  assert.deepEqual(parseStreamCodecTypes("  video  \n\n"), ["video"]);
});

test("parseStreamCodecTypes treats missing output as no streams", () => {
  for (const input of ["", "   \n \n", null, undefined]) {
    assert.deepEqual(parseStreamCodecTypes(input), []);
  }
});

test("audioPresenceFromCodecTypes answers the silent-clip case, which is the ordinary one", () => {
  // A /still-to-clip output is video-only, and server.js documents mixing one
  // of those with a Kling clip as the normal /merge input. It must read as
  // "no audio", NOT as a fault.
  assert.equal(audioPresenceFromCodecTypes(["video"]), false);
  assert.equal(audioPresenceFromCodecTypes(["video", "audio"]), true);
  // Stream order is not ours to assume.
  assert.equal(audioPresenceFromCodecTypes(["audio", "video"]), true);
  assert.equal(audioPresenceFromCodecTypes(["video", "data", "subtitle"]), false);
});

test("audioPresenceFromCodecTypes refuses to guess when the probe said nothing", () => {
  // Any file ffmpeg is about to read has at least one stream, so empty output
  // means the probe itself produced nothing — the caller escalates instead of
  // picking a branch. This is the whole reason the query does not use
  // `-select_streams a`: that form makes a silent clip and a broken probe
  // produce identical output.
  assert.equal(audioPresenceFromCodecTypes([]), null);
  assert.equal(audioPresenceFromCodecTypes(null), null);
  assert.equal(audioPresenceFromCodecTypes(undefined), null);
});
