# syntax=docker/dockerfile:1
# The build stage always runs on the builder's own platform and cross-compiles: Go targets arm64 natively, so a
# multi-arch build never runs the compiler under QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:9ce231b28998b32e116927c61aa5c406183061d4f3f2d61b292c88e7f6bdf7ca AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
# The module and build caches are BuildKit cache mounts: they speed up rebuilds and never end up in the image.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ku-server ./apps/ku-server \
 && mkdir /data /keys

# The debug variant adds busybox (/busybox/sh, already on PATH). PaaS terminals (Dokploy, Coolify) only offer `bash` or
# `sh`, and without one operators cannot run `ku-server key show` or `user invite`. Whoever can exec into the container
# already has everything the process has, so the shell adds no privilege. Still nonroot, still no package manager.
FROM gcr.io/distroless/static-debian12:debug-nonroot@sha256:d5563cc7f2f44313f332e91138cc8c6a158899afeeeab2fce3b0f9ccdb3cf9ee
COPY --from=build /out/ku-server /ku-server
COPY --from=build --chown=65532:65532 /data /data
# /keys is where VAULT_MASTER_KEY_FILE=/keys/master_key lives. It is deliberately not part of /data (and has no
# VOLUME): a backup of the database volume must not carry the key. Mount a named volume there.
COPY --from=build --chown=65532:65532 /keys /keys
ARG VERSION=dev
LABEL org.opencontainers.image.title="kuukura" org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/victorlunam/kuukura"
ENV VAULT_ADDR=:8080 VAULT_STORAGE=sqlite VAULT_SQLITE_PATH=/data/kuukura.db
VOLUME /data
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/ku-server", "healthcheck"]
ENTRYPOINT ["/ku-server"]
CMD ["serve"]
