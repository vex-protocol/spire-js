#!/bin/sh
# Docker HEALTHCHECK: GET /healthz (Node global fetch; no curl/wget/apk in node:alpine)
set -euf
P="$(/bin/sh /app/deploy/resolve-spire-listen-port.sh)"
export P
# shellcheck disable=SC2016
exec node -e 'fetch("http://127.0.0.1:"+process.env.P+"/healthz").then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))'
