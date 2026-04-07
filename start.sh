#!/bin/sh
set -e

PERSIST="${OPENHOST_APP_DATA_DIR:-/data}"
PG_DATA="$PERSIST/pgdata"
ADMIN_PASS_FILE="$PERSIST/.admin_password"

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

# ---------------------------------------------------------------------------
# Generate and persist admin password
# ---------------------------------------------------------------------------
if [ ! -f "$ADMIN_PASS_FILE" ]; then
    ADMIN_PASS=$(head -c 32 /dev/urandom | base64 | tr -d '\n/+=' | head -c 24)
    echo -n "$ADMIN_PASS" > "$ADMIN_PASS_FILE"
    chmod 600 "$ADMIN_PASS_FILE"
fi
ADMIN_PASS=$(cat "$ADMIN_PASS_FILE")

echo "======================================"
echo "Miniflux admin user:     admin"
echo "Miniflux admin password: $ADMIN_PASS"
echo "======================================"

# ---------------------------------------------------------------------------
# Miniflux configuration
# ---------------------------------------------------------------------------
export DATABASE_URL="user=miniflux dbname=miniflux sslmode=disable host=/run/postgresql"
export RUN_MIGRATIONS=1
export CREATE_ADMIN=1
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD="$ADMIN_PASS"
export LISTEN_ADDR=0.0.0.0:8080

# Derive base URL from OpenHost environment variables
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

exec /usr/bin/miniflux
