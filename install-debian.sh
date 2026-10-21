#!/bin/sh
# Debian 13 amd64 / arm64 / armhf (package availability checked by apt).
set -eu
if ! command -v apt-get >/dev/null 2>&1; then
    echo 'This installer requires Debian/Ubuntu with apt-get.' >&2
    exit 1
fi
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    python3 python3-gi python3-gst-1.0 gir1.2-gstreamer-1.0 gir1.2-gst-plugins-bad-1.0 util-linux \
    gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad gstreamer1.0-libav gstreamer1.0-nice gstreamer1.0-x libbcg729-0
cd "$(dirname "$0")"
if [ ! -e config.toml ]; then
    (umask 077; cp config.example.toml config.toml)
fi
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'
python3 -c 'from webrtc_media import available; missing = available(); print("Missing WebRTC plugins:", missing); raise SystemExit(bool(missing))'
python3 -c 'from media import available; missing = {k: v for k, v in available().items() if v}; print("Missing codecs:", missing); raise SystemExit(bool(missing))'
printf '%s\n' 'Installed. Edit config.toml, then run ./run.sh --check and ./run.sh.'
