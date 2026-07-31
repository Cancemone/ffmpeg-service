const test = require("node:test");
const assert = require("node:assert/strict");
const { assertStorageEnv, publicUrlFor } = require("../storage");

const FULL_ENV = {
  STORAGE_ENDPOINT: "https://ref.storage.supabase.co/storage/v1/s3",
  STORAGE_REGION: "eu-central-1",
  STORAGE_ACCESS_KEY_ID: "id",
  STORAGE_SECRET_ACCESS_KEY: "secret",
  STORAGE_BUCKET: "media",
  STORAGE_PUBLIC_URL: "https://ref.supabase.co/storage/v1/object/public/media",
};

test("assertStorageEnv passes when every var is present", () => {
  assert.doesNotThrow(() => assertStorageEnv(FULL_ENV));
});

test("assertStorageEnv names every missing var at once", () => {
  const partial = { ...FULL_ENV };
  delete partial.STORAGE_BUCKET;
  delete partial.STORAGE_REGION;
  assert.throws(
    () => assertStorageEnv(partial),
    /STORAGE_REGION.*STORAGE_BUCKET|STORAGE_BUCKET.*STORAGE_REGION/s,
  );
});

test("publicUrlFor joins base and key exactly like the app's storageUrl()", () => {
  assert.equal(
    publicUrlFor("runs/2f8c/merged.mp4", FULL_ENV),
    "https://ref.supabase.co/storage/v1/object/public/media/runs/2f8c/merged.mp4",
  );
});

test("publicUrlFor tolerates a trailing slash in the configured base", () => {
  assert.equal(
    publicUrlFor("a.mp4", { ...FULL_ENV, STORAGE_PUBLIC_URL: FULL_ENV.STORAGE_PUBLIC_URL + "/" }),
    "https://ref.supabase.co/storage/v1/object/public/media/a.mp4",
  );
});
