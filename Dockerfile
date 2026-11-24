# syntax=docker/dockerfile:1
#
# keycordon image. The binary is fully static (CGO_ENABLED=0), so the runtime
# layer only needs CA certificates for the upstream's TLS and tzdata for logs.
#
#   docker build -t keycordon:latest .
#   docker run --rm -p 8318:8318 \
#     -e KEYCORDON_MASTER_KEY=... \
#     keycordon:latest serve -upstream http://host.docker.internal:8317
#
# In China, add --build-arg GOPROXY=https://goproxy.cn,direct --build-arg
# GOSUMDB=sum.golang.google.cn to the build.
#
# See docker/README.md for the volume and master-key story.

ARG GO_VERSION=1.27
# The official proxy is the default, so a build outside China needs no
# arguments. In China pass --build-arg GOPROXY=https://goproxy.cn,direct .
ARG GOPROXY=https://proxy.golang.org,direct
ARG GOSUMDB=sum.golang.org

# ---- build -----------------------------------------------------------------
FROM docker.io/library/golang:${GO_VERSION}-alpine AS build
# `apk add gcc musl-dev` is only needed if a future dependency wants cgo; the
# build below sets CGO_ENABLED=0, so the minimal image is enough.
ARG GOPROXY
ARG GOSUMDB
ARG VERSION=dev
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOPROXY=${GOPROXY} \
    GOSUMDB=${GOSUMDB} \
    GOFLAGS=-mod=mod \
    GOTOOLCHAIN=local
WORKDIR /src

# Dependencies first: this layer is reused while only source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/keycordon ./cmd/keycordon \
 && /out/keycordon version

# ---- runtime ---------------------------------------------------------------
FROM docker.io/library/alpine:3.21
LABEL maintainer="XiaoXi <admin@soraharu.com>"

# ca-certificates: the upstream may be https.
# tzdata: log timestamps honour TZ.
# A fixed non-root uid: a file-write bug cannot become root in the container.
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 keycordon \
 && adduser  -S -u 10001 -G keycordon -h /var/lib/keycordon -s /sbin/nologin keycordon \
 && mkdir -p /var/lib/keycordon /etc/keycordon \
 && chown -R keycordon:keycordon /var/lib/keycordon

COPY --from=build /out/keycordon /usr/local/bin/keycordon
COPY docker/keycordon.yaml /etc/keycordon/config.yaml

ENV HOME=/var/lib/keycordon
WORKDIR /var/lib/keycordon
# The master key lives here (vault.master_key_file). Mount a named volume to
# keep it across container recreation, which keeps placeholders — and thus the
# upstream's prompt cache — stable across restarts (design 7.3).
VOLUME ["/var/lib/keycordon"]
EXPOSE 8318
USER keycordon

ENTRYPOINT ["keycordon"]
CMD ["serve", "-config", "/etc/keycordon/config.yaml"]
