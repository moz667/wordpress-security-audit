#!/bin/sh

ENGINE="${WHITELIST_ENGINE:-/usr/local/bin/lib/wsa-auto-add-whitelists-engine.sh}"
exec "$ENGINE" --stage=themes "$@"
