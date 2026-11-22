#!/bin/sh
# Ubuntu packages the UI (gpui) needs to build, as in the README's
# Requirements. Run by the CI workflow.
set -eu
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    build-essential pkg-config \
    libxkbcommon-dev libxkbcommon-x11-dev libxcb1-dev \
    libfreetype-dev libfontconfig-dev libwayland-dev
