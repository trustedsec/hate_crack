#!/bin/bash
#
set -euo pipefail

TORRENT_DIR="${TR_TORRENT_DIR:-}"
TORRENT_NAME="${TR_TORRENT_NAME:-}"

if [ -z "$TORRENT_DIR" ] || [ -z "$TORRENT_NAME" ]; then
    exit 0
fi

TORRENT_PATH="${TORRENT_DIR}/${TORRENT_NAME}"

SEVENZ_BIN=$(command -v 7z || command -v 7za || true)
if [ -n "$SEVENZ_BIN" ]; then
    if [ -f "$TORRENT_PATH" ] && [[ "$TORRENT_PATH" == *.7z ]]; then
        "$SEVENZ_BIN" x -sdel "$TORRENT_PATH" -o"$TORRENT_DIR"
    elif [ -d "$TORRENT_PATH" ]; then
        find "$TORRENT_PATH" -maxdepth 2 -type f -name "*.7z" -print0 | while IFS= read -r -d '' zfile; do
            "$SEVENZ_BIN" e -sdel "$zfile"
        done
    fi
fi

if [ -n "$PPID" ]; then
    kill "$PPID"
fi
