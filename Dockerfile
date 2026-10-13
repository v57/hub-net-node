# docker build -t hub-net-node .
FROM golang:1.26-alpine AS build
WORKDIR /src/hub-net-node
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/v57/hub-net-node/version.Build=${VERSION}" \
    -o /out/hub-net-node ./cmd/hub-net-node

FROM alpine:3.22
RUN addgroup -S -g 65532 hub-net-node \
    && adduser -S -D -H -u 65532 -G hub-net-node hub-net-node \
    && mkdir -p /var/lib/hub-net-node \
    && chown hub-net-node:hub-net-node /var/lib/hub-net-node
COPY --from=build /out/hub-net-node /usr/local/bin/hub-net-node
LABEL org.opencontainers.image.title="hub-net-node" \
      org.opencontainers.image.description="Unprivileged Hub Network rendezvous node"
USER 65532:65532
VOLUME ["/var/lib/hub-net-node"]
EXPOSE 1964/tcp 1964/udp
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:1964/healthz || exit 1
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/hub-net-node"]
CMD ["-listen", "0.0.0.0:1964", "-state-dir", "/var/lib/hub-net-node"]
