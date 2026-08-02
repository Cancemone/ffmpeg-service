// Pure duration arithmetic shared by /overlay and /merge. It lives here rather
// than inside server.js because server.js runs app.listen() at module scope and
// process.exit(1)s on a missing AUTH_TOKEN / storage env — `node --test` cannot
// require it. Same reasoning as validation.js: keep the numbers testable and
// leave server.js a thin HTTP shell.

// Cross-fade length inserted at every /merge junction.
//
// DUPLICATED LITERAL. The source of truth is MERGE_TRANSITION_SEC in
// creative-studio/lib/creative/ffmpeg.ts — a separate repo, so there is no
// module to import. Changing it on one side only is a silent bug: the Vercel
// side sizes the single global-VO mp3 against
// sum(clip durations) - MERGE_TRANSITION_SEC * (clips - 1), which is exactly
// the timeline the xfade chain in /merge produces.
const MERGE_TRANSITION_SEC = 0.4;

// How much longer than the video the audio may be before /overlay treats it as
// a caller bug rather than rounding.
//
// The final ffmpeg call already hard-bounds the output with `-t videoDur`, so
// anything inside this window is cut inaudibly and failing the request would
// only wedge a run that is fine. The window sits:
//   - BELOW the smallest systematic overrun the transition budget can cause
//     (MERGE_TRANSITION_SEC — even a two-clip ad has one junction), so the bug
//     this guard was added for is always reported;
//   - AT the threshold the trim branch this replaced used, so no request that
//     used to succeed starts failing. That branch trimmed above 0.3s, and the
//     trim was a no-op against the `-t videoDur` below it, so everything up to
//     0.3s already produced byte-identical output with a 200.
// The lower bound matters as much as the upper one: this window is the ONLY
// slack the global-VO path has left. terminal_atempo fits the mp3 to exactly
// the modelled merged duration, and that model is built from AUTHORED clip
// durations while /merge lays out the timeline from the durations it probes off
// the downloaded files — mp3 frame granularity (~26ms), ffprobe estimates and a
// provider clip returning a few frames short of what it was asked for all land
// here. So does the caller's deliberate 0.2s slack (the template preview only
// atempo-fits a VO once it exceeds the clip by more than its SAFETY_PAD_SEC,
// and sends the remainder unfitted).
const OVERLAY_MAX_OVERFLOW_SEC = 0.3;

// Returns by how much the audio outlives the video, rounded to whole
// milliseconds so float noise never reaches a log line or a response body.
function overlayAudioOverflow(audioDur, videoDur) {
  const overflowSec = Number((audioDur - videoDur).toFixed(3));
  return { overflowSec, exceedsTolerance: overflowSec > OVERLAY_MAX_OVERFLOW_SEC };
}

module.exports = {
  MERGE_TRANSITION_SEC,
  OVERLAY_MAX_OVERFLOW_SEC,
  overlayAudioOverflow,
};
