Miniflux minimalist RSS reader for OpenHost. Runs as a single Docker container with PostgreSQL bundled inside.

## How it works

On first boot, the container:
1. Initializes a PostgreSQL database in OpenHost persistent storage
2. Creates the miniflux database with hstore extension
3. Generates and persists an admin password
4. Runs Miniflux migrations and creates the admin user
5. Starts Miniflux with the correct base URL derived from OpenHost environment variables

## Deploying

```bash
oh app deploy https://github.com/imbue-ai/openhost-miniflux --wait
```

The app will be available at `miniflux.{zone_domain}`.

## Admin credentials

- Username: `admin`
- Password: stored in `$OPENHOST_APP_DATA_DIR/.admin_password`

Retrieve the password from the container logs on first boot or via the file browser app.

## Data

All persistent data lives in `$OPENHOST_APP_DATA_DIR/`:
- `pgdata/` — PostgreSQL data directory (feeds, articles, user settings)
- `.admin_password` — generated admin password
- `postgresql.log` — PostgreSQL log file

## API access

Miniflux exposes several APIs for mobile app integration:
- Native REST API (`/v1/...`)
- Fever API (`/fever/`) — compatible with Reeder, Unread, etc.
- Google Reader API (`/reader/`) — compatible with many RSS clients

## Resources

Needs ~512MB RAM (Miniflux ~30MB + PostgreSQL ~100-200MB + headroom) and 0.25 CPU cores.

## Files

- `Dockerfile` — multi-stage build: extracts Miniflux binary, adds PostgreSQL on Alpine
- `start.sh` — initializes PostgreSQL, configures Miniflux via env vars, launches both
- `openhost.toml` — OpenHost app manifest
