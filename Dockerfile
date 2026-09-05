FROM miniflux/miniflux:latest AS miniflux

FROM alpine:3.20

RUN apk add --no-cache \
    bash \
    postgresql16 \
    postgresql16-client \
    postgresql16-contrib \
    python3

COPY --from=miniflux /usr/bin/miniflux /usr/bin/miniflux

COPY start.sh /app/start.sh
COPY auth_proxy.py /app/auth_proxy.py
COPY auto_subscribe.py /app/auto_subscribe.py
RUN chmod +x /app/start.sh

RUN mkdir -p /run/postgresql && chown postgres:postgres /run/postgresql

EXPOSE 8080

CMD ["/app/start.sh"]
