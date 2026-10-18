# keyryx as a published image.
#
# Static and distroless: CGO off is what makes the binary runnable on
# distroless static and what makes cross-compiling to arm64 free. The base
# images are pinned by digest, not by tag: a tag can move under an operator
# without anyone choosing that, a digest cannot (gate:
# scripts/base-images-pinned-by-digest.sh). The digests are the ones the
# sibling Go services of this stack already build on.
#
# NEEDS BUILDKIT for $BUILDPLATFORM (the default in Docker 23 and later).

FROM --platform=$BUILDPLATFORM golang@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c AS build
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/keyryx ./cmd/keyryx

FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.title="keyryx"
LABEL org.opencontainers.image.description="Key custody and an independent witness for the agent-governance record, off every request path."
LABEL org.opencontainers.image.source="https://github.com/TAIPANBOX/keyryx"
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/keyryx /usr/local/bin/keyryx
# Numeric on purpose: a kubelet with runAsNonRoot cannot verify a name. A
# launcher runs each role under its own uid anyway (custody and witness never
# share one).
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/keyryx"]
