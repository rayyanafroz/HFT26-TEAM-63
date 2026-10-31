#!/bin/bash
# Starts the ShadowLens UI on its own (mock data, no backend) and opens it in the browser.
# Stop it with Ctrl+C in this window.
cd "$(dirname "$0")" || exit 1
PORT=8801
echo "ShadowLens demo: http://localhost:$PORT/?mock=1   (pitch page: add #/pitch)"
( sleep 1; open "http://localhost:$PORT/?mock=1" ) &
exec python3 -m http.server "$PORT" --bind 127.0.0.1
