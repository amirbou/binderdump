#!/usr/bin/env bash
# Grab-and-go installer. Run from an extracted binderdump-<tag> bundle:
#   tar xzf binderdump-<tag>.tgz && cd binderdump-<tag> && ./install.sh
# Delegates to install_dissector.sh in bundle mode, which resolves the
# dissector, corpus, profile, extcap, and capture binary from this directory.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
exec "$here/install_dissector.sh" --bundle "$@"
