# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.25-alpine AS build
# version is baked into the binary via -ldflags; pass it with
# --build-arg VERSION=$(git describe --tags --always --dirty).
# Defaults to "dev" so plain `docker build` still works.
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/subconverter-ng ./cmd/subconverter-ng

# ---- runtime stage ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app
USER app
COPY --from=build /out/subconverter-ng /usr/local/bin/subconverter-ng
EXPOSE 25500
ENTRYPOINT ["subconverter-ng", "serve", "--listen", ":25500"]
