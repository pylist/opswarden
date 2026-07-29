# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d AS caddy-source
USER 0:0
RUN setcap -r /usr/bin/caddy && test -z "$(getcap /usr/bin/caddy)"

FROM caddy-source AS caddy-config
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY deploy/OpsWardenProxy.caddy /etc/caddy/OpsWardenProxy.caddy
RUN OPSWARDEN_HOSTNAME=opswarden.invalid \
    OPSWARDEN_TLS_EMAIL=opswarden@example.invalid \
    OPSWARDEN_FORWARDED_FOR='{remote_host}' \
    caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null

FROM golang:1.25.12-alpine3.23@sha256:cc985ef6f9c3bf9ece7488129c9abe0a150388ccdfa428d886fc709dca0b230a AS health-build
ARG TARGETARCH
ENV CGO_ENABLED=0 \
    GO111MODULE=off \
    GOOS=linux
WORKDIR /src
COPY deploy/caddy-healthcheck/main.go ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    test -n "${TARGETARCH}" && \
    GOARCH="${TARGETARCH}" go build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -buildid=" \
      -o /out/caddy-healthcheck . && \
    chmod 0555 /out/caddy-healthcheck

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
LABEL org.opencontainers.image.title="OpsWarden Caddy" \
      org.opencontainers.image.description="Minimal pinned TLS reverse proxy for OpsWarden" \
      org.opencontainers.image.version="2.10.2"
ENV XDG_CONFIG_HOME=/config \
    XDG_DATA_HOME=/data
COPY --from=caddy-source --chown=10002:10002 /usr/bin/caddy /usr/local/bin/caddy
COPY --from=health-build --chown=10002:10002 /out/caddy-healthcheck /usr/local/bin/caddy-healthcheck
COPY --from=caddy-config --chown=10002:10002 /etc/caddy/Caddyfile /etc/caddy/Caddyfile
COPY --from=caddy-config --chown=10002:10002 /etc/caddy/OpsWardenProxy.caddy /etc/caddy/OpsWardenProxy.caddy
WORKDIR /data
USER 10002:10002
EXPOSE 443
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/caddy-healthcheck"]
ENTRYPOINT ["/usr/local/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
