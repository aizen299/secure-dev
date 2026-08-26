# SecureOps API and migration binaries.
#
# The API orchestrates and never executes untrusted target content, so this
# image deliberately contains no scanner binaries, no shell tooling, and no
# package managers (CLAUDE.md §14.1).

FROM golang:1.27-alpine AS build
WORKDIR /src

# Cache dependency download separately from the source layer.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/api ./cmd/api && \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/worker ./cmd/worker && \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w" \
        -o /out/migrate ./cmd/migrate

# Distroless: no shell, no package manager, minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/api /usr/local/bin/api
COPY --from=build /out/worker /usr/local/bin/worker
COPY --from=build /out/migrate /usr/local/bin/migrate
COPY migrations /migrations

# Rule §15.10: containers run as non-root.
USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/api"]
