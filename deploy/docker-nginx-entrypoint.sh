#!/bin/sh
# Match Spire listen port (src/spireListenPort.ts) using the same rules as
# deploy/resolve-spire-listen-port.sh.
set -euf
PORT="$(/bin/sh /opt/resolve-spire-listen-port.sh)"
# sed delimiter must not appear in the port; use # for special chars
sed "s#__SPIRE_UPSTREAM_PORT__#$PORT#g" /etc/nginx/nginx.conf.template > /tmp/nginx.conf
exec nginx -c /tmp/nginx.conf -g "daemon off;"
