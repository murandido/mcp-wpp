# syntax=docker/dockerfile:1

# ---- build: Go + SQLCipher -------------------------------------------------
FROM docker.io/library/golang:1.26-trixie@sha256:19ce7a1fdc59527aa568805ea100c380900d059d251e914fb86e11fd0ce68952 AS build
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends libsqlcipher-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN make build VERSION=${VERSION}

# ---- test: the full suite against SQLCipher (make container-test) ---------
FROM build AS test
ARG DEBIAN_FRONTEND=noninteractive
# The OCR tests run the real tesseract here.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng tesseract-ocr-por poppler-utils \
    && rm -rf /var/lib/apt/lists/*
# The image ships Debian's SQLCipher, which has FTS5, Tesseract and
# pdftotext: require them here.
ENV WPP_MCP_REQUIRE_FTS5=1 \
    WPP_MCP_REQUIRE_TESSERACT=1 \
    WPP_MCP_REQUIRE_PDFTOTEXT=1
RUN make vet fmt test smoke e2e

# ---- runtime ---------------------------------------------------------------
FROM docker.io/library/debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0 AS runtime
ARG DEBIAN_FRONTEND=noninteractive

# ffmpeg is only needed by send_audio_message for non-Opus input; build with
# --build-arg WITH_FFMPEG=1 to include it. Tesseract (Portuguese and English)
# serves extract_image_text when the daemon runs with -ocr; pdftotext
# (poppler-utils) reads PDF documents for chat notes.
ARG WITH_FFMPEG=0
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends ca-certificates libsqlcipher1 \
       tesseract-ocr tesseract-ocr-eng tesseract-ocr-por poppler-utils \
    && if [ "$WITH_FFMPEG" = "1" ]; then apt-get install -y --no-install-recommends ffmpeg; fi \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 10001 -m -d /home/app app \
    && mkdir -p /data/store \
    && chown -R app:app /data \
    && chmod 0700 /data/store
COPY --from=build /src/bin/wpp-mcp /usr/local/bin/wpp-mcp

USER app
WORKDIR /data

# The daemon listens on the container interface so Docker can publish the
# port; publish it on the host's loopback only (see compose.yaml). Every route
# except the probes needs the bearer token in /data/store/token, and the
# Host/Origin guard still rejects non-loopback hostnames.
ENV WPP_MCP_STORE=/data/store \
    WPP_MCP_ADDR=0.0.0.0:8765 \
    WPP_MCP_KEY_FILE=/run/secrets/wpp_mcp_key
EXPOSE 8765
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["wpp-mcp", "healthcheck"]

ENTRYPOINT ["wpp-mcp"]
CMD ["serve", "-allow-remote"]
