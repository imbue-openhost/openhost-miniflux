FROM miniflux/miniflux:latest AS miniflux

FROM alpine:3.20

RUN apk add --no-cache \
    postgresql16 \
    postgresql16-client \
    postgresql16-contrib

COPY --from=miniflux /usr/bin/miniflux /usr/bin/miniflux

COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

RUN mkdir -p /run/postgresql && chown postgres:postgres /run/postgresql

EXPOSE 8080

CMD ["/app/start.sh"]
