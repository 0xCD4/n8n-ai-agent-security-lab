#!/usr/bin/env bash
# Build the 60 second demo video from the HTML scenes.
#
# Requirements:
#   - a Chromium or Chrome binary (set CHROME, default: chromium)
#   - ffmpeg with libx264
#
# The script renders each scene to a 1920x1080 PNG, then encodes an
# H.264 MP4 with one still per scene and the durations from timing.txt.
# Output: assets/security-review-demo-en.mp4
#
# Everything shown in the scenes is committed repository output.
# The build is deterministic apart from encoder version differences.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
chrome="${CHROME:-chromium}"
out="$root/assets/security-review-demo-en.mp4"
frames="$here/frames"

mkdir -p "$frames"

# 1. Render scenes to stills.
# The window size is taller than the scene because headless Chrome subtracts
# window UI from --window-size. Scenes are anchored top-left at 1920x1080,
# so the encode step crops the extra rows away.
while read -r scene duration; do
  case "$scene" in ''|'#'*) continue ;; esac
  png="$frames/${scene%.html}.png"
  "$chrome" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
    --hide-scrollbars --force-device-scale-factor=1 \
    --window-size=1920,1300 --screenshot="$png" \
    "file://$here/scenes/$scene" >/dev/null 2>&1
  echo "rendered $scene"
done < "$here/timing.txt"

# 2. Expand the timing into an explicit 30 fps frame sequence.
# Symlinking one entry per output frame avoids concat-demuxer duration quirks.
seq_dir="$frames/sequence"
rm -rf "$seq_dir"
mkdir -p "$seq_dir"
index=0
while read -r scene duration; do
  case "$scene" in ''|'#'*) continue ;; esac
  png="$frames/${scene%.html}.png"
  count=$((duration * 30))
  for _ in $(seq 1 "$count"); do
    index=$((index + 1))
    ln -s "$png" "$(printf '%s/frame-%05d.png' "$seq_dir" "$index")"
  done
done < "$here/timing.txt"

# 3. Encode H.264 MP4, 1080p, 30 fps, silent.
ffmpeg -y -hide_banner -loglevel error \
  -framerate 30 -i "$seq_dir/frame-%05d.png" \
  -vf "crop=1920:1080:0:0" \
  -pix_fmt yuv420p \
  -c:v libx264 -preset slow -crf 20 -movflags +faststart \
  "$out"

# The per-frame symlink sequence is only an encode input.
rm -rf "$seq_dir"

echo "wrote $out"
