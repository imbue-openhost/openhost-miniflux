Miniflux minimalist RSS reader for Cloud in a Bottle. Runs as a single Docker container with PostgreSQL bundled inside and Cloud in a Bottle single sign-on.

## How it works

On first boot, the container:
1. Initializes a PostgreSQL database in Cloud in a Bottle persistent storage.
2. Creates the `miniflux` database with the `hstore` extension.
3. Runs Miniflux migrations.
4. Starts Miniflux on `127.0.0.1:8081` behind a tiny auth-proxy sidecar on port 8080.
5. Derives `BASE_URL` from `OPENHOST_ZONE_DOMAIN` / `OPENHOST_APP_NAME` / `OPENHOST_ROUTER_URL`.
6. Subscribes the owner to the Cloud in a Bottle GitHub releases feed.

First-start subscriptions are defined by `AUTO_SUBSCRIBE_FEEDS` in `start.sh`.
They run only for newly initialized persistent storage. If setup is interrupted,
it resumes on the next start; after setup succeeds, removing a feed does not
cause it to be recreated.

## Authentication

Miniflux does not have its own login flow here — sign-in is handled by the zone's Cloud in a Bottle identity.

The Cloud in a Bottle router authenticates the visitor and, on requests from the zone owner, sets a trusted `X-OpenHost-Is-Owner: true` header. The router enforces auth on every non-public path (everything except `/healthcheck` and `/js/` for this app) *before* the request reaches the container, and it strips any inbound `X-OpenHost-*` headers so a client cannot forge them.

The auth-proxy sidecar (`auth_proxy.py`) reads that header. When it is `true`, the sidecar stamps the request with `X-Openhost-User: admin` and forwards it to Miniflux. Miniflux is configured with `AUTH_PROXY_HEADER=X-Openhost-User`, `AUTH_PROXY_USER_CREATION=1`, `TRUSTED_REVERSE_PROXY_NETWORKS=127.0.0.1/32`, and `DISABLE_LOCAL_AUTH=1`, so:

- The zone owner is auto-logged-in as the `admin` Miniflux user on their first visit (the account is auto-created).
- The username/password form is hidden — there is no local password to remember or leak.
- Only requests from 127.0.0.1 (the sidecar) are trusted to assert the user header.
- The sidecar strips both `X-OpenHost-Is-Owner` and any client-supplied `X-Openhost-User` from the request before forwarding, so neither the router's internal header nor a hostile client's injected header can reach Miniflux as-is — the only `X-Openhost-User` Miniflux ever sees is the one the sidecar stamps itself.

## Deploying

```bash
oh app deploy https://github.com/imbue-openhost/bottled-miniflux --wait
```

The app will be available at `miniflux.{zone_domain}`. Browse to it and you're signed in — no separate password.

## Data

All persistent data lives in `$OPENHOST_APP_DATA_DIR/`:
- `pgdata/` — PostgreSQL data directory (feeds, articles, user settings, plus `postgresql.log`)

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
# Should end at the Cloud in a Bottle zone's /login page (the router gates the request).

# Header spoofing attempt:
curl -IL -H "X-OpenHost-Is-Owner: true" https://miniflux.<zone-domain>/
# Should also end at the zone login — the router strips inbound X-OpenHost-* headers,
# so a forged owner header never reaches the sidecar.
```

## Development

Unit tests cover the sidecar's pure helper functions (header stripping — the
header-injection defense — and port parsing). They need only `pytest`; the
proxy itself imports nothing outside the Python standard library.

```bash
pip install pytest
pytest tests/ -q
```

The HTTP handler's socket I/O is exercised at deploy time via the smoke-test
commands above.

## Files

- `Dockerfile` — multi-stage build: extracts the Miniflux binary, then adds PostgreSQL and Python 3 on Alpine.
- `start.sh` — initializes PostgreSQL, configures Miniflux and first-start feeds, starts Miniflux on loopback, then starts the auth-proxy sidecar; supervises both so the container exits (and is restarted by Cloud in a Bottle) if either child dies.
- `auto_subscribe.py` — installs app-defined feeds through Miniflux's normal subscription flow on a fresh installation.
- `auth_proxy.py` — the reverse proxy that translates Cloud in a Bottle's `X-OpenHost-Is-Owner` signal into Miniflux's auth-proxy header.
- `openhost.toml` — Cloud in a Bottle app manifest. Only `/healthcheck` and `/js/` are marked as public paths.
