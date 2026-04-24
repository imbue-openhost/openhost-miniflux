FROM miniflux/miniflux:latest AS miniflux

FROM alpine:3.20

RUN apk add --no-cache \
    bash \
    postgresql16 \
    postgresql16-client \
    postgresql16-contrib \
    python3 \
    py3-pip

# Install PyJWT with cryptography (for RS256) and requests, isolated from the
# system Python. We use a venv so we can pip install on Alpine 3.20 without
# --break-system-packages.
RUN python3 -m venv /opt/auth-venv \
 && /opt/auth-venv/bin/pip install --no-cache-dir \
        'PyJWT[crypto]==2.9.0' \
        'requests==2.32.3'

COPY --from=miniflux /usr/bin/miniflux /usr/bin/miniflux

COPY start.sh /app/start.sh
COPY auth_proxy.py /app/auth_proxy.py
RUN chmod +x /app/start.sh

RUN mkdir -p /run/postgresql && chown postgres:postgres /run/postgresql

EXPOSE 8080

CMD ["/app/start.sh"]
