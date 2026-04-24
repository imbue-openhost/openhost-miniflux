#!/bin/bash
# `bash` (not `sh`) is required: we rely on `wait -n` to block until the
# first of two backgrounded processes exits so we can tear down the other
# one cleanly. Alpine's /bin/sh (busybox ash) does not support `wait -n`.
set -e

PERSIST="${OPENHOST_APP_DATA_DIR:-/data}"
PG_DATA="$PERSIST/pgdata"

mkdir -p "$PERSIST"

# PostgreSQL socket directory (tmpfs, recreated each boot)
mkdir -p /run/postgresql
chown postgres:postgres /run/postgresql

# ---------------------------------------------------------------------------
# Initialize PostgreSQL on first boot
# ---------------------------------------------------------------------------
if [ ! -f "$PG_DATA/PG_VERSION" ]; then
    mkdir -p "$PG_DATA"
    chown postgres:postgres "$PG_DATA"
    su postgres -c "initdb -D '$PG_DATA' --auth=trust"

    # Local-only connections with trust auth
    cat > "$PG_DATA/pg_hba.conf" <<EOF
local all all trust
EOF

    # Tune for low-memory container environment
    cat >> "$PG_DATA/postgresql.conf" <<EOF

# OpenHost tuning
shared_buffers = 64MB
work_mem = 4MB
maintenance_work_mem = 16MB
max_connections = 10
listen_addresses = ''
EOF
fi

# Ensure correct ownership
chown -R postgres:postgres "$PG_DATA"

# Clean up stale PID from unclean shutdown
rm -f "$PG_DATA/postmaster.pid"

# Start PostgreSQL
su postgres -c "pg_ctl start -D '$PG_DATA' -l '$PERSIST/postgresql.log' -w -o '-k /run/postgresql'"

# ---------------------------------------------------------------------------
# Create miniflux database on first boot
# ---------------------------------------------------------------------------
if ! su postgres -c "psql -h /run/postgresql -tAc \"SELECT 1 FROM pg_database WHERE datname='miniflux'\"" | grep -q 1; then
    su postgres -c "createuser -h /run/postgresql miniflux"
    su postgres -c "createdb -h /run/postgresql -O miniflux miniflux"
    su postgres -c "psql -h /run/postgresql -c 'ALTER USER miniflux WITH SUPERUSER'"
    su postgres -c "psql -h /run/postgresql -d miniflux -c 'CREATE EXTENSION IF NOT EXISTS hstore'"
fi

# Remove the legacy admin password file. Authentication is handled by the
# OpenHost zone's SSO; this file is never written by current code and is
# cleared here so it cannot be mistaken for a live credential.
rm -f "$PERSIST/.admin_password"

# ---------------------------------------------------------------------------
# Miniflux configuration
# ---------------------------------------------------------------------------
export DATABASE_URL="user=miniflux dbname=miniflux sslmode=disable host=/run/postgresql"
export RUN_MIGRATIONS=1

# Miniflux listens on loopback only. The auth-proxy sidecar (see
# auth_proxy.py) fronts it on :8080 and is the only component allowed to
# assert OpenHost identity via the trusted proxy header.
export LISTEN_ADDR=127.0.0.1:8081

# Proxy auth: Miniflux trusts the X-Openhost-User header but only when the
# request arrives from 127.0.0.1 (the sidecar). Accept user auto-creation so
# the `admin` miniflux user gets minted on the first owner login; disable the
# local username/password form entirely so no one can bypass SSO.
export AUTH_PROXY_HEADER=X-Openhost-User
export AUTH_PROXY_USER_CREATION=1
export TRUSTED_REVERSE_PROXY_NETWORKS=127.0.0.1/32
export DISABLE_LOCAL_AUTH=1

export FORCE_REFRESH_INTERVAL=1

# Derive base URL from OpenHost environment variables so Miniflux generates
# correct absolute URLs (cookies, OPML links, emails, etc.).
if [ -n "$OPENHOST_ZONE_DOMAIN" ]; then
    APP_SUBDOMAIN="${OPENHOST_APP_NAME:-miniflux}"
    DOMAIN_NAME="${APP_SUBDOMAIN}.${OPENHOST_ZONE_DOMAIN}"

    case "$OPENHOST_ZONE_DOMAIN" in
        lvh.me|*.lvh.me|localhost|*.localhost)
            ROUTER_PORT=""
            if [ -n "$OPENHOST_ROUTER_URL" ]; then
                ROUTER_PORT=$(echo "$OPENHOST_ROUTER_URL" | sed -n 's/.*:\([0-9]*\)$/\1/p')
            fi
            export BASE_URL="http://${DOMAIN_NAME}${ROUTER_PORT:+:$ROUTER_PORT}/"
            ;;
        *)
            export BASE_URL="https://${DOMAIN_NAME}/"
            ;;
    esac
fi

# ---------------------------------------------------------------------------
# Launch both processes under the shell so we can supervise them together.
# The shell stays PID 1, catches SIGTERM from Docker/OpenHost, forwards it
# to both children, and reaps them. If either child exits the whole
# container exits too so OpenHost can restart it.
# ---------------------------------------------------------------------------
echo "[start.sh] Starting miniflux on 127.0.0.1:8081"
/usr/bin/miniflux &
MINIFLUX_PID=$!

# Give miniflux a moment to bind the socket before the sidecar starts
# accepting requests. Not strictly required (the sidecar returns 502 until
# miniflux is up), but avoids a noisy first-request failure.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(0.5); sys.exit(0) if not s.connect_ex(("127.0.0.1", 8081)) else sys.exit(1)' 2>/dev/null; then
        break
    fi
    sleep 0.5
done

# If the miniflux process already died, surface the exit code.
if ! kill -0 "$MINIFLUX_PID" 2>/dev/null; then
    wait "$MINIFLUX_PID"
    exit $?
fi

echo "[start.sh] Starting auth-proxy on 0.0.0.0:8080"
/opt/auth-venv/bin/python3 /app/auth_proxy.py &
PROXY_PID=$!

# Forward SIGTERM / SIGINT to both children so the container stops cleanly.
# Note: `exec` would have discarded this trap, so we keep the shell alive as
# PID 1 and use `wait -n` to block until one of the two processes exits.
trap 'kill -TERM "$MINIFLUX_PID" "$PROXY_PID" 2>/dev/null; wait' TERM INT

# Block until either child exits, then tear down the survivor and exit with
# the first child's status. `wait -n` is a bash builtin (not available in
# POSIX sh / busybox ash) and returns as soon as any backgrounded job exits.
#
# We explicitly disable `set -e` around the `wait -n` call: with errexit on,
# a child that exits non-zero (or a trap interrupting the wait) would cause
# the shell to exit immediately before the explicit teardown (`kill` +
# `wait`) runs, leaving the surviving process orphaned.
set +e
wait -n "$MINIFLUX_PID" "$PROXY_PID"
EXIT_CODE=$?
set -e
echo "[start.sh] Child exited (code=$EXIT_CODE); stopping container"
kill -TERM "$MINIFLUX_PID" "$PROXY_PID" 2>/dev/null || true
# Allow remaining processes to drain; don't let `set -e` abort if they too
# exit non-zero.
wait || true
exit "$EXIT_CODE"
