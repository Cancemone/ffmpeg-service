# ffmpeg-service

Video post-processing sidecar for [creative-studio](https://github.com/Cancemone/creative-studio).
Express + ffmpeg, deployed manually on a VPS. Every endpoint is called only
through `creative-studio/lib/creative/ffmpeg.ts` — never directly.

## Endpoints

All POST, all require `Authorization: Bearer $AUTH_TOKEN`, all take an
`output_key` and return a public URL of the object written to storage.

| Path | Body | Returns |
|---|---|---|
| `/merge` | `clips[]`, `output_key`, `transition_duration?`, `width?`, `height?` | `{url, duration, output_key}` |
| `/overlay` | `video_url`, `audio_url`, `output_key` | `{url, duration, output_key}` |
| `/still-to-clip` | `image_url`, `duration_sec`, `output_key`, `width?`, `height?` | `{url, duration, output_key}` |
| `/burn-subs` | `video_url`, `output_key`, `style?`, `language?`, `words?` | `{url, subtitles, reason?}` |
| `/color-grade` | `video_url`, `output_key`, `grade` | `{url, duration, grade}` |
| `/mix-background` | `video_url`, `music_url`, `output_key` | `{url, duration}` |
| `/extract-audio` | `video_url`, `output_key` | `{url, output_key}` |
| `/extract-thumbnail` | `video_url`, `output_key`, `timestamp_sec?` | `{url, width, height, duration}` |
| `/atempo` | `audio_url`, `output_key`, `atempo` | `{url, duration, applied_atempo}` |
| `/health` (GET, no auth) | — | `{status, ffmpeg}` |

Dimensions default to 720x1280 (9:16) when `width`/`height` are omitted.

`/burn-subs` returns `subtitles: false` (with the un-subtitled source uploaded
under `output_key`) for exactly three transcription gaps: no Whisper
credentials, the Whisper call failed, or Whisper returned no words. Every other
failure — download, ffprobe, ASS build, the ffmpeg burn, the upload — is a 500.
Shipping a service fault as a `200` wrote a broken asset to the caller's final
key and hid the fault behind a legitimate-looking response.

## Storage

Supabase Storage via its S3-compatible endpoint, bucket `media`, public read.
The returned URL must stay byte-identical to creative-studio's
`storageUrl()` — `keyFromUrl()` parses it back and the cleanup crons depend on
that round-trip.

## Deploy

```bash
cd /opt/ffmpeg-service && git pull && npm ci --omit=dev && pm2 restart ffmpeg-service
```

First-time provisioning of a VPS (runtime, nginx, TLS, pm2, smoke): [DEPLOY.md](DEPLOY.md).

## Local checks

```bash
npm test                     # unit tests, no network
node scripts/smoke.mjs       # end-to-end against a deployed instance
```
