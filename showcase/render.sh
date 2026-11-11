#!/bin/sh
# Renders each showcase screen to a 1600x1200 PNG in showcase/screens/ (uses Google Chrome, headless).
cd "$(dirname "$0")"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
mkdir -p screens
n=1
for s in cover investigate report approvals architecture; do
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --window-size=1600,1200 --screenshot="$PWD/screens/0${n}-$s.png" "file://$PWD/index.html?screen=$s" 2>/dev/null
  n=$((n+1))
done
ls -1 screens
