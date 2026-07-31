const test = require("node:test");
const assert = require("node:assert/strict");
const { buildAssContent, toAssTime, chunkWords } = require("../subtitles");

const WORDS = [
  { word: "one", start: 0.0, end: 0.4 },
  { word: "two", start: 0.4, end: 0.8 },
  { word: "three", start: 0.8, end: 1.2 },
  { word: "four", start: 1.2, end: 1.6 },
  { word: "five", start: 1.6, end: 2.0 },
];

test("toAssTime formats hours, minutes and centiseconds", () => {
  assert.equal(toAssTime(0), "0:00:00.00");
  assert.equal(toAssTime(75.25), "0:01:15.25");
});

test("chunkWords groups into fixed-size runs", () => {
  assert.equal(chunkWords(WORDS, 4).length, 2);
  assert.equal(chunkWords(WORDS, 4)[0].length, 4);
});

test("at 720x1280 the default style line is unchanged from the pre-format build", () => {
  const { content } = buildAssContent("bold_outline", WORDS, { width: 720, height: 1280 });
  assert.ok(
    content.includes(
      "Style: Default,Arial,48,&H00FFFFFF,&H000000FF,&H00000000,&H80000000,1,0,0,0,100,100,0,0,1,3.5,0,2,10,10,170,1",
    ),
    content,
  );
  assert.ok(content.includes("PlayResX: 720"));
  assert.ok(content.includes("PlayResY: 1280"));
});

test("a shorter frame scales font size and bottom margin proportionally", () => {
  const { content } = buildAssContent("bold_outline", WORDS, { width: 1280, height: 720 });
  assert.ok(content.includes("PlayResX: 1280"));
  assert.ok(content.includes("PlayResY: 720"));
  // 48 * (720/1280) = 27 ; 170 * (720/1280) = 96
  assert.ok(content.includes("Style: Default,Arial,27,"), content);
  assert.ok(content.includes(",96,1"), content);
});

test("karaoke emits one dialogue line per 4-word chunk with \\kf tags", () => {
  const { content, chunkCount } = buildAssContent("karaoke", WORDS, { width: 720, height: 1280 });
  assert.equal(chunkCount, 2);
  assert.match(content, /\{\\kf40\}one/);
});

test("popup emits one dialogue line per word", () => {
  const { chunkCount } = buildAssContent("popup", WORDS, { width: 720, height: 1280 });
  assert.equal(chunkCount, WORDS.length);
});

test("an unknown style falls back to bold_outline instead of throwing", () => {
  const { content } = buildAssContent("no_such_style", WORDS, { width: 720, height: 1280 });
  assert.ok(content.includes("Style: Default,Arial,48,"));
});
