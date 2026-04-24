Miniflux minimalist RSS reader for OpenHost. Runs as a single Docker container with PostgreSQL bundled inside and OpenHost single sign-on.

## How it works

On first boot, the container:
1. Initializes a PostgreSQL database in OpenHost persistent storage.
2. Creates the `miniflux` database with the `hstore` extension.
3. Runs Miniflux migrations.
4. Starts Miniflux on `127.0.0.1:8081` behind a tiny auth-proxy sidecar on port 8080.
5. Derives `BASE_URL` from `OPENHOST_ZONE_DOMAIN` / `OPENHOST_APP_NAME` / `OPENHOST_ROUTER_URL`.

## Authentication

Miniflux does not have its own login flow here — sign-in is handled by the zone's OpenHost identity.

The auth-proxy sidecar (`auth_proxy.py`) verifies the visitor's `zone_auth` JWT cookie against the router's JWKS at `$OPENHOST_ROUTER_URL/.well-known/jwks.json`. When the cookie is a valid RS256 token with `sub == "owner"`, the sidecar stamps the request with `X-Openhost-User: admin` and forwards it to Miniflux. Miniflux is configured with `AUTH_PROXY_HEADER=X-Openhost-User`, `AUTH_PROXY_USER_CREATION=1`, `TRUSTED_REVERSE_PROXY_NETWORKS=127.0.0.1/32`, and `DISABLE_LOCAL_AUTH=1`, so:

- The zone owner is auto-logged-in as the `admin` Miniflux user on their first visit (the account is auto-created).
- The username/password form is hidden — there is no local password to remember or leak.
- Only requests from 127.0.0.1 (the sidecar) are trusted to assert the user header.
- Any client-supplied `X-Openhost-User` header is stripped before it can reach Miniflux, so header injection cannot grant access.

The sidecar caches the JWKS for 10 minutes and falls back to the cached copy on router outages (matching the pattern in `openhost-mirotalk-p2p`).

## Deploying

```bash
oh app deploy https://github.com/imbue-openhost/openhost-miniflux --wait
```

The app will be available at `miniflux.{zone_domain}`. Browse to it and you're signed in — no separate password.

## Data

All persistent data lives in `$OPENHOST_APP_DATA_DIR/`:
- `pgdata/` — PostgreSQL data directory (feeds, articles, user settings)
- `postgresql.log` — PostgreSQL log file

## API access

Miniflux exposes several APIs for mobile app integration:
- Native REST API (`/v1/...`)
- Fever API (`/fever/`) — compatible with Reeder, Unread, etc.
- Google Reader API (`/reader/`) — compatible with many RSS clients

Because `DISABLE_LOCAL_AUTH=1`, these APIs cannot be used with a username/password. Create API keys from the Miniflux settings page (`Settings → API Keys`) once you're signed in as the owner.

## Resources

Needs ~512 MB RAM (Miniflux ~30 MB + PostgreSQL ~100-200 MB + sidecar ~30 MB + headroom) and 0.25 CPU cores.

## Smoke testing a deployment

After `oh app deploy`, verify the SSO gate from an authenticated session (owner) and an unauthenticated session:

```bash
# With a valid zone_auth cookie from the zone's /login flow:
curl -b cookies.txt -IL https://miniflux.<zone-domain>/
# Should end in 200 at /unread (you are the owner, auto-signed-in as admin).

# Without any cookies:
curl -IL https://miniflux.<zone-domain>/
# Should end at the OpenHost zone's /login page.

# Header spoofing attempt:
curl -IL -H "X-Openhost-User: admin" https://miniflux.<zone-domain>/
# Should also end at the zone login — the sidecar strips the header.
```

## Development

Unit tests (pure helpers; JWT verification, cookie parsing):

```bash
pip install 'PyJWT[crypto]==2.9.0' requests pytest cryptography
pytest tests/ -q
```

## Files

- `Dockerfile` — multi-stage build: extracts Miniflux binary, adds PostgreSQL and a Python venv with `PyJWT[crypto]` + `requests` on Alpine.
- `start.sh` — initializes PostgreSQL, configures Miniflux via env vars, starts Miniflux on loopback, then starts the auth-proxy sidecar; supervises both so the container exits (and is restarted by OpenHost) if either child dies.
- `auth_proxy.py` — the JWT-verifying reverse proxy that translates OpenHost SSO into Miniflux's auth-proxy header.
- `openhost.toml` — OpenHost app manifest. Only `/healthcheck` is marked as a public path.
