# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ku-server ./cmd/ku-server \
 && mkdir /data /keys

FROM gcr.io/distroless/static-debian12:nonroot
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
