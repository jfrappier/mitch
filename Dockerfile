# Container image for Mitch.
#
# Build for your own machine (works on Apple Silicon and Intel):
#
#   docker build -t mitch .
#
# The binary is cross-compiled in the first stage, so a multi-platform build
# only compiles Go and never emulates the other CPU.
# Docs: https://docs.docker.com/build/building/multi-platform/
#
# The final image is distroless "static" on Debian 13: no shell or package
# manager, CA certificates for TLS to Vault, and the "nonroot" user.
# Docs: https://github.com/GoogleContainerTools/distroless
#
# See docs/docker.md for how to run it.

# The Go version must match the "go" line in go.mod.
ARG GO_VERSION=1.26.11

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build

# Set by docker buildx for each platform being built.
# Docs: https://docs.docker.com/build/building/variables/#multi-platform-build-arguments
ARG TARGETOS
ARG TARGETARCH

# Build information shown by "mitch version".
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src

# Download modules first, so this layer is cached until go.mod or go.sum change.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

# CGO_ENABLED=0 makes a static binary, which the distroless static image needs.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
      -ldflags "-X github.com/jfrappier/mitch/internal/version.Version=${VERSION} -X github.com/jfrappier/mitch/internal/version.Commit=${COMMIT} -X github.com/jfrappier/mitch/internal/version.BuildDate=${BUILD_DATE}" \
      -o /out/mitch ./cmd/mitch

# An empty folder for the database, owned by the nonroot user (uid 65532),
# so a Docker volume mounted on /data starts out writable by Mitch.
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=build /out/mitch /usr/local/bin/mitch
COPY --from=build --chown=65532:65532 /out/data /data

# Keep the database on a volume, so scans survive the container.
ENV MITCH_DB=/data/mitch.db
VOLUME ["/data"]
WORKDIR /data

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/mitch"]
CMD ["help"]
