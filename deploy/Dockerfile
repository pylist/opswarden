# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM node:22.18.0-alpine3.22@sha256:1b2479dd35a99687d6638f5976fd235e26c5b37e8122f786fcd5fe231d63de5b AS web-build
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    TZ=UTC
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.25.12-alpine3.23@sha256:cc985ef6f9c3bf9ece7488129c9abe0a150388ccdfa428d886fc709dca0b230a AS go-build
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
ARG SOURCE_DATE_EPOCH=0
ENV CGO_ENABLED=0 \
    GOOS=linux \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    TZ=UTC
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
COPY --from=web-build /src/internal/webui/dist/ ./internal/webui/dist/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    test -n "${TARGETARCH}" && \
    GOARCH="${TARGETARCH}" go build \
      -mod=readonly \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -buildid= -X opswarden/internal/app.Version=${VERSION}" \
      -o /out/opswarden ./cmd/opswarden && \
    GOARCH="${TARGETARCH}" go build \
      -mod=readonly \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -buildid=" \
      -o /out/healthcheck ./deploy/healthcheck && \
    mkdir -p /out/state && \
    chmod 0555 /out/opswarden /out/healthcheck && \
    chmod 0700 /out/state

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="OpsWarden" \
      org.opencontainers.image.description="Single-host encrypted credential and asset management service" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=go-build --chown=10001:10001 /out/opswarden /usr/local/bin/opswarden
COPY --from=go-build --chown=10001:10001 /out/healthcheck /usr/local/bin/healthcheck
COPY --from=go-build --chown=10001:10001 --chmod=0700 /out/state /var/lib/opswarden
WORKDIR /var/lib/opswarden
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/healthcheck"]
ENTRYPOINT ["/usr/local/bin/opswarden"]
