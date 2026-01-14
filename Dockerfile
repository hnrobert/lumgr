FROM golang:1.24-bookworm AS build
WORKDIR /src

COPY go.mod ./

# If you add external deps later, uncomment:
# RUN go mod download

COPY . ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/lumgrd ./cmd/lumgrd

FROM alpine:3.20
RUN apk add --no-cache ca-certificates shadow

COPY --from=build /out/lumgrd /usr/local/bin/lumgrd

EXPOSE 14392
ENV LUMGR_LISTEN=:14392

ENTRYPOINT ["/usr/local/bin/lumgrd"]
