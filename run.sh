#!/bin/bash
# Chay production bang waitress (cross-platform: Windows + Linux).
# Cau hinh qua env: LISTEN_HOST, LISTEN_PORT, THREADS.

rm -rf __pycache__
waitress-serve \
  --host="${LISTEN_HOST:-127.0.0.1}" \
  --port="${LISTEN_PORT:-8084}" \
  --threads="${THREADS:-8}" \
  app:app
