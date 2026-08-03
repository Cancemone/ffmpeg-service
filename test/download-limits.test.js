const test = require("node:test");
const assert = require("node:assert/strict");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const {
  MAX_DOWNLOAD_BYTES,
  MERGE_DOWNLOAD_CONCURRENCY,
  declaredTooLarge,
  mapWithConcurrency,
  streamToFile,
} = require("../download-limits");

test("declaredTooLarge rejects a body that announces more than the cap", () => {
  assert.equal(declaredTooLarge(String(MAX_DOWNLOAD_BYTES + 1)), true);
  assert.equal(declaredTooLarge(String(MAX_DOWNLOAD_BYTES)), false);
  assert.equal(declaredTooLarge("0"), false);
});

// A chunked or gzipped response carries no usable Content-Length. That is not
// an error — the byte counter around the stream is what actually enforces the
// cap; the header is only the cheap early-out.
test("declaredTooLarge treats a missing or unparseable header as 'unknown'", () => {
  for (const header of [null, undefined, "", "  ", "lots", "-5", "1e9999"]) {
    assert.equal(declaredTooLarge(header), false, `${header} should not trip the guard`);
  }
});

test("declaredTooLarge takes an explicit cap", () => {
  assert.equal(declaredTooLarge("2048", 1024), true);
  assert.equal(declaredTooLarge("512", 1024), false);
});

test("mapWithConcurrency preserves input order", async () => {
  const out = await mapWithConcurrency([5, 1, 3], 2, async (ms, i) => {
    await new Promise((r) => setTimeout(r, ms));
    return `${i}:${ms}`;
  });
  assert.deepEqual(out, ["0:5", "1:1", "2:3"]);
});

test("mapWithConcurrency never runs more than `limit` tasks at once", async () => {
  let live = 0;
  let peak = 0;
  await mapWithConcurrency(Array.from({ length: 12 }, (_, i) => i), 4, async () => {
    live++;
    peak = Math.max(peak, live);
    await new Promise((r) => setTimeout(r, 5));
    live--;
  });
  assert.equal(peak, 4);
});

test("mapWithConcurrency handles an empty list and a limit above the list size", async () => {
  assert.deepEqual(await mapWithConcurrency([], 4, async () => "x"), []);
  assert.deepEqual(await mapWithConcurrency([1], 4, async (n) => n * 2), [2]);
});

test("mapWithConcurrency rejects with the first error and starts nothing new", async () => {
  const started = [];
  await assert.rejects(
    mapWithConcurrency([0, 1, 2, 3, 4, 5], 2, async (i) => {
      started.push(i);
      // Item 1 fails before its worker can pick up anything else, so the only
      // task still running when the failure lands is item 0.
      if (i === 1) throw new Error(`boom ${i}`);
      await new Promise((r) => setTimeout(r, 20));
    }),
    /boom 1/,
  );
  assert.deepEqual(started, [0, 1]);
});

// The endpoints unlink their temp files in `finally`. If a rejected fan-out
// left downloads still writing, cleanup would race them and leave orphans.
test("mapWithConcurrency waits for in-flight tasks before rejecting", async () => {
  let finished = 0;
  await assert.rejects(
    mapWithConcurrency([0, 1, 2, 3], 2, async (i) => {
      if (i === 0) throw new Error("fast failure");
      await new Promise((r) => setTimeout(r, 20));
      finished++;
    }),
    /fast failure/,
  );
  assert.equal(finished, 1, "the sibling task must have settled before we rejected");
});

// `fetch().body` is a web ReadableStream — build the same thing here rather
// than a Node stream, so the adapter inside streamToFile is exercised too.
function webStreamOf(chunks) {
  return new ReadableStream({
    start(controller) {
      for (const c of chunks) controller.enqueue(typeof c === "string" ? Buffer.from(c) : c);
      controller.close();
    },
  });
}

async function withTmpFile(fn) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "dl-test-"));
  try {
    return await fn(path.join(dir, "body.bin"));
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
}

test("streamToFile writes the body to disk and reports its size", async () => {
  await withTmpFile(async (dest) => {
    const written = await streamToFile(webStreamOf(["hello ", "world"]), dest);
    assert.equal(written, 11);
    assert.equal(await fsp.readFile(dest, "utf-8"), "hello world");
  });
});

// The whole point of streaming: the cap has to bite mid-body, not after the
// entire response has been held in memory.
test("streamToFile aborts once the running total passes the cap", async () => {
  await withTmpFile(async (dest) => {
    const chunk = Buffer.alloc(64, 1);
    await assert.rejects(
      streamToFile(webStreamOf([chunk, chunk, chunk]), dest, 100),
      /100-byte cap/,
    );
  });
});

test("streamToFile accepts a body that lands exactly on the cap", async () => {
  await withTmpFile(async (dest) => {
    assert.equal(await streamToFile(webStreamOf([Buffer.alloc(100, 1)]), dest, 100), 100);
  });
});

// server.js hands streamToFile a body straight from fetch. A data: URL gives
// us a real undici response — no listener, no network — so the adapter is
// pinned against the object it actually receives, not just a hand-built one.
test("streamToFile accepts a body produced by fetch itself", async () => {
  await withTmpFile(async (dest) => {
    const res = await fetch(`data:text/plain;base64,${Buffer.from("from fetch").toString("base64")}`);
    assert.equal(await streamToFile(res.body, dest), 10);
    assert.equal(await fsp.readFile(dest, "utf-8"), "from fetch");
  });
});

test("the merge fan-out cap is a small positive integer", () => {
  assert.ok(Number.isInteger(MERGE_DOWNLOAD_CONCURRENCY));
  assert.ok(MERGE_DOWNLOAD_CONCURRENCY >= 1 && MERGE_DOWNLOAD_CONCURRENCY <= 8);
});
