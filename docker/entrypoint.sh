#!/bin/sh
set -eu

role="${PROXY_HUB_ROLE:-server}"
case "$role" in
  server)
    exec python /app/server.py
    ;;
  collector)
    exec python /app/collector.py
    ;;
  *)
    echo "PROXY_HUB_ROLE must be server or collector" >&2
    exit 2
    ;;
esac
