# Build Go backend
FROM golang:1.25-alpine AS build_go_stage

RUN apk add --no-cache git ca-certificates tzdata gcc musl-dev

WORKDIR /app/server

COPY code/server/go.mod code/server/go.sum ./
RUN go mod download && go mod verify

COPY code/server/ ./
# CGO_ENABLED: Makes go binary statically linked and does not rely on system C libaries, important for docker alpine images
# GOOS: Target OS to build on
# GOARCH: Target CPU architecture to build on
# ldflags "-w -s": Strip debug information to reduce binary size (harder to reverse engineer FF)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o bootstrap

# Final runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    ffmpeg \
    python3 \
    py3-pip \
    && pip3 install --no-cache-dir yt-dlp --break-system-packages

WORKDIR /app

COPY --from=build_go_stage /app/server/streaming-api .

EXPOSE 8080

# Run as non-root user for security
RUN addgroup -g 1001 -S appuser && \
    adduser -u 1001 -S appuser -G appuser && \
    chown -R appuser:appuser /app

USER appuser

CMD ["./bootstrap"]
