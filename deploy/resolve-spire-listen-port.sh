#!/bin/sh
# Resolves the TCP port Spire will bind when API_PORT is unset. Must match
# resolveSpireListenPort() in src/spireListenPort.ts.
set -euf
DEFAULT_SPIRE_API_PORT=16777
if [ -n "${API_PORT-}" ] && [ "$API_PORT" != "" ]; then
    printf %s "$API_PORT"
    exit 0
fi
printf %s "$DEFAULT_SPIRE_API_PORT"
