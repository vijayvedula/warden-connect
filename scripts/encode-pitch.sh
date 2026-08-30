#!/usr/bin/env bash
# Turn the recorded frames into the files that actually get posted.
#
#     node scripts/record-pitch.mjs --fps 30 --out build/pitch
#     scripts/encode-pitch.sh
#
# ## Why there are three files and not five
#
# LinkedIn and Substack want the same thing, and saying so is more useful than manufacturing a
# difference. LinkedIn accepts MP4 with H.264 video and AAC audio at 48 kHz, 16:9 landscape,
# up to 4096x2304 and 5 GB. Substack accepts MP4 with H.264 and AAC, calls 1080p the right
# balance, and asks for the bitrate to stay at or under 8 Mbps. One encode satisfies both, so
# there is one social file rather than two identical ones with different names.
#
# The **silent AAC track is not an oversight to be optimised away.** The film has no sound, but
# LinkedIn documents AAC at 48 kHz for compatibility and players behave better with a track
# present than absent, so one is added deliberately.
#
# The GIF exists because a README cannot autoplay or loop anything else. GitHub sanitises
# <video> out of Markdown, and an .mp4 committed to the repository renders as a link. An
# animated GIF is the only thing that plays continuously in a README, which is what it is for
# and the only reason to accept its size.
set -euo pipefail
cd "$(dirname "$0")/.."

readonly FRAMES=build/pitch/frames
readonly OUT=build/pitch
readonly FPS=30
readonly NAME=warden-connect-pitch

[ -d "$FRAMES" ] || { echo "no frames — run scripts/record-pitch.mjs first" >&2; exit 1; }
COUNT=$(find "$FRAMES" -name 'f*.png' | wc -l | tr -d ' ')
echo "  $COUNT frames at ${FPS}fps, 3840x2160 -> 1920x1080"

# Every encode downsamples 2:1 with Lanczos. That is where the sharpness comes from: the text
# was rasterised at twice the output resolution, so the downsample averages four samples per
# pixel instead of guessing at one.
readonly DOWN="scale=1920:1080:flags=lanczos"

# --- 1 · the master, at the resolution it was actually drawn.
#
# The frames are 3840x2160 because that is what the browser rasterises at devicePixelRatio 2 —
# what any Retina screen shows. Encoding only a 1080p output threw three quarters of those
# pixels away, and a viewer comparing the video against the live page on the same screen was
# comparing an upscaled 1080p against a native 2160p. It looked soft because it WAS soft.
# Measured: the encoder loses 0.55/255 against the captured frame, so resolution was the only
# thing left that could account for it. No rescale here; this is pixel-exact.
ffmpeg -y -loglevel error -framerate "$FPS" -i "$FRAMES/f%06d.png" \
  -c:v libx264 -preset slow -crf 18 -pix_fmt yuv420p -movflags +faststart \
  "$OUT/$NAME-2160p.mp4"

# --- 1b · and a 1080p downsample, for anywhere that wants a smaller file.
ffmpeg -y -loglevel error -framerate "$FPS" -i "$FRAMES/f%06d.png" \
  -vf "$DOWN" -c:v libx264 -preset slow -crf 16 -pix_fmt yuv420p -movflags +faststart \
  "$OUT/$NAME-1080p.mp4"

# --- 2 · the one that gets posted. H.264 + a silent 48 kHz AAC track, capped under 8 Mbps.
# 1080p, because that is what both platforms call the safe default and both transcode anyway.
# If a feed's own transcode looks soft, upload the 2160p instead — LinkedIn accepts up to
# 4096x2304 and Substack accepts 4K.
ffmpeg -y -loglevel error -framerate "$FPS" -i "$FRAMES/f%06d.png" \
  -f lavfi -i anullsrc=channel_layout=stereo:sample_rate=48000 \
  -vf "$DOWN" -c:v libx264 -preset slow -crf 19 -maxrate 7M -bufsize 14M -pix_fmt yuv420p \
  -c:a aac -b:a 96k -ar 48000 -shortest -movflags +faststart \
  "$OUT/$NAME-social-1080p.mp4"

# --- 3 · the README loop: the algebra beat, where the three sets converge and the core lights.
# Two passes, because a GIF generated against a generic palette bands badly on a dark ground
# and this film is almost entirely one dark ground.
# `-t`, not `-frames:v`. The latter counts OUTPUT frames, so with an fps=12 filter in the
# chain it asked for 345 frames at 12fps — 28 seconds of source, running straight through the
# end of the slide and into the next one. The first GIF built here was exactly that.
readonly LOOP_FROM=88 LOOP_SECS=11.5
START=$(python3 -c "print(int($LOOP_FROM * $FPS))")
ffmpeg -y -loglevel error -start_number "$START" -framerate "$FPS" -i "$FRAMES/f%06d.png" \
  -t "$LOOP_SECS" -vf "fps=12,scale=1120:-1:flags=lanczos,palettegen=stats_mode=diff" \
  "$OUT/palette.png"
ffmpeg -y -loglevel error -start_number "$START" -framerate "$FPS" -i "$FRAMES/f%06d.png" \
  -i "$OUT/palette.png" -t "$LOOP_SECS" \
  -lavfi "fps=12,scale=1120:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3" \
  -loop 0 "$OUT/$NAME-loop.gif"
rm -f "$OUT/palette.png"

# --- 4 · a poster frame, for anywhere that wants a thumbnail rather than a player.
ffmpeg -y -loglevel error -i "$FRAMES/f000090.png" -vf "$DOWN" -q:v 2 "$OUT/$NAME-poster.jpg"

echo
printf '  %-44s %s\n' "file" "size"
for f in "$OUT/$NAME"*; do
  printf '  %-44s %s\n' "$(basename "$f")" "$(du -h "$f" | cut -f1 | tr -d ' ')"
done
echo
ffprobe -v error -show_entries format=duration,bit_rate -show_entries stream=codec_name,width,height,r_frame_rate \
  -of default=noprint_wrappers=1 "$OUT/$NAME-social-1080p.mp4" | sed 's/^/  /'
