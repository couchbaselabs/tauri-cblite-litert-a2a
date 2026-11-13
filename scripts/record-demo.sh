#!/bin/bash
# Real screen recording of the control-room page: Xvfb + WebKit viewer + ffmpeg x11grab.
W=1920; H=1080; OUT=${OUT:-$HOME/a2a-test/rec/demo-raw.mp4}
mkdir -p "$(dirname "$OUT")"
pkill -f viewer.py 2>/dev/null; pkill Xvfb 2>/dev/null; pkill -f 'target-sec/debug/a2a-node' 2>/dev/null; sleep 1
rm -rf ~/a2a-test/demo-field
nohup bash "$(dirname "$0")/demo-field-inspection.sh" > ~/a2a-test/rec/live.log 2>&1 &
for i in $(seq 1 120); do
  A=$(curl -s http://127.0.0.1:18801/agents 2>/dev/null)
  [[ "$A" == *'"branch"'* && "$A" == *'"hq"'* ]] && break; sleep 1
done
echo "mesh up after ${i}s"; sleep 4
Xvfb :99 -nocursor -screen 0 ${W}x${H}x24 >/dev/null 2>&1 &
sleep 2
unset WAYLAND_DISPLAY; export GDK_BACKEND=x11
export DISPLAY=:99 WEBKIT_DISABLE_COMPOSITING_MODE=1 WEBKIT_DISABLE_DMABUF_RENDERER=1 LIBGL_ALWAYS_SOFTWARE=1
ffmpeg -y -loglevel error -f x11grab -draw_mouse 0 -framerate 30 -video_size ${W}x${H} -i :99 -c:v libx264 -preset veryfast -crf 20 -pix_fmt yuv420p "$OUT" &
FF=$!
sleep 1
python3 $(dirname "$0")/record-viewer.py "http://127.0.0.1:18801/demo/all?autoplay=1" $W $H >/dev/null 2>&1 &
VW=$!
timeout 420 tail --pid=$VW -f /dev/null
echo "viewer closed"; sleep 1
kill -INT $FF; wait $FF 2>/dev/null
kill $VW 2>/dev/null; pkill Xvfb; pkill -f 'target-sec/debug/a2a-node'
ls -la "$OUT"
