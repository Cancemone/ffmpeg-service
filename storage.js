// Object storage backend — Supabase Storage via its S3-compatible endpoint.
//
// Replaces the previous Cloudflare R2 backend. The bucket (`media`) and the
// key layout (`runs/<id>/…`) are shared with the Next.js app, which writes the
// same objects through the Supabase JS client. The public URL this module
// returns MUST match creative-studio's lib/creative/storage.ts:storageUrl(),
// because keyFromUrl() parses it back into a key and the cleanup crons rely on
// that round-trip.

const fsp = require("fs").promises;
const {
  S3Client,
  PutObjectCommand,
  DeleteObjectCommand,
} = require("@aws-sdk/client-s3");

const REQUIRED_VARS = [
  "STORAGE_ENDPOINT",
  "STORAGE_REGION",
  "STORAGE_ACCESS_KEY_ID",
  "STORAGE_SECRET_ACCESS_KEY",
  "STORAGE_BUCKET",
  "STORAGE_PUBLIC_URL",
];

function assertStorageEnv(env = process.env) {
  const missing = REQUIRED_VARS.filter((name) => !env[name]);
  if (missing.length > 0) {
    throw new Error(`Missing required storage env vars: ${missing.join(", ")}`);
  }
}

function publicUrlFor(key, env = process.env) {
  const base = String(env.STORAGE_PUBLIC_URL || "").replace(/\/+$/, "");
  return `${base}/${key}`;
}

let client = null;

function getClient(env = process.env) {
  if (!client) {
    client = new S3Client({
      // Supabase Storage speaks path-style S3 only; virtual-host style 404s.
      forcePathStyle: true,
      region: env.STORAGE_REGION,
      endpoint: env.STORAGE_ENDPOINT,
      credentials: {
        accessKeyId: env.STORAGE_ACCESS_KEY_ID,
        secretAccessKey: env.STORAGE_SECRET_ACCESS_KEY,
      },
    });
  }
  return client;
}

// No CacheControl on purpose: retries overwrite deterministic keys
// (runs/<id>/merged.mp4, runs/<id>/global-vo.mp3), so a long-lived or
// immutable cache would serve pre-retry bytes from the CDN.
async function uploadFile(localPath, key, contentType) {
  const body = await fsp.readFile(localPath);
  await getClient().send(
    new PutObjectCommand({
      Bucket: process.env.STORAGE_BUCKET,
      Key: key,
      Body: body,
      ContentType: contentType || "video/mp4",
    }),
  );
  return publicUrlFor(key);
}

// Only the smoke script uses this — the production pipeline never deletes
// from here (the Next.js cleanup crons own object lifecycle).
async function deleteFile(key) {
  await getClient().send(
    new DeleteObjectCommand({ Bucket: process.env.STORAGE_BUCKET, Key: key }),
  );
}

module.exports = { assertStorageEnv, publicUrlFor, uploadFile, deleteFile };
