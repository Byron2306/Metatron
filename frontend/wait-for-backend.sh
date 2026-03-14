#!/bin/sh
set -e

# Wait for the backend service to be resolvable and respond healthy.
# By default this waits indefinitely. To set a max wait in seconds, set
# the environment variable `MAX_WAIT` to a positive integer.
MAX_WAIT=${MAX_WAIT:-0}
i=0
printf "Waiting for backend to become resolvable and healthy"
while true; do
  if getent hosts backend >/dev/null 2>&1; then
    if wget -qO- --timeout=2 --tries=1 http://backend:8001/api/health >/dev/null 2>&1; then
      echo " -> backend reachable and healthy"
      break
    fi
  fi
  i=$((i+1))
  printf "."
  if [ "$MAX_WAIT" -ne 0 ] && [ $i -ge $MAX_WAIT ]; then
    echo "\nReached MAX_WAIT ($MAX_WAIT)s; continuing to start nginx (backend still unreachable)."
    break
  fi
  sleep 1
done

# Exec nginx in foreground
exec nginx -g 'daemon off;'
