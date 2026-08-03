// ASS subtitle generation, parameterised by output geometry.
//
// PlayResX/Y are set to the real video dimensions, and font size / margins are
// scaled relative to the original 1280-high design so a 16:9 (1280x720) render
// does not get 48px text sitting 170px above the bottom edge — which on a
// 720-high frame would land near the vertical centre.
//
// ASS colour format is &HAABBGGRR (alpha, blue, green, red — reversed from RGB).
// BorderStyle=1 → outline+shadow, BorderStyle=3 → opaque box behind the text.

const REFERENCE_HEIGHT = 1280;

// Outline and shadow are NOT scaled: they are sub-pixel-ish values (3.5, 4)
// where rounding would visibly change the look, and libass already renders
// them relative to PlayRes.
function styleLine(opts, scale) {
  const px = (v) => Math.max(1, Math.round(v * scale));
  return [
    "Style: Default",
    "Arial",
    px(opts.fontSize),
    opts.primary,
    opts.secondary,
    opts.outlineColour,
    opts.back,
    1, // Bold
    0, // Italic
    0, // Underline
    0, // StrikeOut
    100, // ScaleX
    100, // ScaleY
    0, // Spacing
    0, // Angle
    opts.borderStyle,
    opts.outline,
    opts.shadow,
    2, // Alignment: bottom-centre
    px(opts.marginLR),
    px(opts.marginLR),
    px(opts.marginV),
    1, // Encoding
  ].join(",");
}

const STYLES = {
  // Large white, thick black outline — the UGC/performance ad standard.
  bold_outline: {
    fontSize: 48,
    primary: "&H00FFFFFF",
    secondary: "&H000000FF",
    outlineColour: "&H00000000",
    back: "&H80000000",
    borderStyle: 1,
    outline: 3.5,
    shadow: 0,
    marginLR: 10,
    marginV: 170,
  },
  // Word-by-word highlight: white text, active word turns yellow.
  karaoke: {
    fontSize: 48,
    primary: "&H00FFFFFF",
    secondary: "&H0000FFFF",
    outlineColour: "&H00000000",
    back: "&H80000000",
    borderStyle: 1,
    outline: 3,
    shadow: 0,
    marginLR: 10,
    marginV: 170,
  },
  // White text on a semi-transparent black box. Maximum readability.
  boxed: {
    fontSize: 42,
    primary: "&H00FFFFFF",
    secondary: "&H000000FF",
    outlineColour: "&H00000000",
    back: "&H96000000",
    borderStyle: 3,
    outline: 0,
    shadow: 4,
    marginLR: 20,
    marginV: 170,
  },
  // White text with a pink neon glow.
  glowing: {
    fontSize: 46,
    primary: "&H00FFFFFF",
    secondary: "&H000000FF",
    outlineColour: "&H00CC44FF",
    back: "&H00CC44FF",
    borderStyle: 1,
    outline: 2,
    shadow: 3,
    marginLR: 10,
    marginV: 170,
  },
  // Word-by-word scale-in pop animation.
  popup: {
    fontSize: 48,
    primary: "&H00FFFFFF",
    secondary: "&H000000FF",
    outlineColour: "&H00000000",
    back: "&H80000000",
    borderStyle: 1,
    outline: 3,
    shadow: 0,
    marginLR: 10,
    marginV: 170,
  },
};

function toAssTime(s) {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return `${h}:${String(m).padStart(2, "0")}:${sec.toFixed(2).padStart(5, "0")}`;
}

function chunkWords(wordList, size) {
  const chunks = [];
  for (let i = 0; i < wordList.length; i += size) {
    chunks.push(wordList.slice(i, i + size));
  }
  return chunks;
}

// Does `words` from the request body describe subtitles we can actually burn?
//
// Everything downstream — chunkWords, toAssTime, the \kf centisecond maths —
// assumes `{ word: string, start: number, end: number }`. A caller that sends
// something else does not get partial subtitles, it gets an ASS file full of
// `undefined` at time NaN burned permanently into the delivered video. So the
// bar is all-or-nothing: one bad entry sends the whole request down the
// transcription path, which either produces correct timings or reports
// `subtitles: false` — both honest answers.
function isUsableWord(w) {
  return (
    w !== null &&
    typeof w === "object" &&
    typeof w.word === "string" &&
    w.word.length > 0 &&
    Number.isFinite(w.start) &&
    Number.isFinite(w.end) &&
    w.end >= w.start
  );
}

function hasUsableWords(words) {
  return Array.isArray(words) && words.length > 0 && words.every(isUsableWord);
}

function buildAssContent(styleKey, wordList, dims) {
  const key = STYLES[styleKey] ? styleKey : "bold_outline";
  const { width, height } = dims;
  const scale = height / REFERENCE_HEIGHT;

  const header = `[Script Info]
ScriptType: v4.00+
PlayResX: ${width}
PlayResY: ${height}
ScaledBorderAndShadow: yes

[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
${styleLine(STYLES[key], scale)}

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
`;

  const lines = [];

  if (key === "karaoke") {
    // \kf duration is in centiseconds.
    for (const chunk of chunkWords(wordList, 4)) {
      const tags = chunk
        .map((w) => `{\\kf${Math.round((w.end - w.start) * 100)}}${w.word}`)
        .join(" ");
      lines.push(
        `Dialogue: 0,${toAssTime(chunk[0].start)},${toAssTime(chunk[chunk.length - 1].end)},Default,,0,0,0,,${tags}`,
      );
    }
  } else if (key === "popup") {
    for (const w of wordList) {
      const tag = "{\\fscx0\\fscy0\\t(0,80,\\fscx100\\fscy100)}";
      lines.push(
        `Dialogue: 0,${toAssTime(w.start)},${toAssTime(w.end)},Default,,0,0,0,,${tag}${w.word}`,
      );
    }
  } else {
    for (const chunk of chunkWords(wordList, 4)) {
      const text = chunk.map((w) => w.word).join(" ");
      const prefix = key === "glowing" ? "{\\blur4}" : "";
      lines.push(
        `Dialogue: 0,${toAssTime(chunk[0].start)},${toAssTime(chunk[chunk.length - 1].end)},Default,,0,0,0,,${prefix}${text}`,
      );
    }
  }

  return { content: header + lines.join("\n") + "\n", chunkCount: lines.length };
}

module.exports = { buildAssContent, chunkWords, toAssTime, hasUsableWords, STYLES };
