#!/bin/sh
# Initialize on first boot (prints the one-time admin token to the log),
# then run the gateway.
set -e
if [ ! -f "${ONEGATE_DATA:-/data}/rootCA.pem" ]; then
  node bin/onegate.js init
fi
if [ $# -eq 0 ]; then set -- start; fi
exec node bin/onegate.js "$@"
