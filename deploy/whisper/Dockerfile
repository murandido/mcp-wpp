# syntax=docker/dockerfile:1
#
# Local speech-to-text for wpp-mcp: whisper.cpp's whisper-server, built from a
# pinned commit, with the multilingual "base" model verified by SHA-256.
# compose.yaml runs it as the optional `whisper` service (profile
# `transcribe`) on an internal network with no internet access; wpp-mcp
# reaches it at http://whisper:8080 and audio never leaves the host.
#
# Build it on the machine that runs it: the default build is tuned for the
# build host's CPU (GGML_NATIVE). Pass --build-arg GGML_NATIVE=OFF for a
# portable image.

ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# ---- build ----------------------------------------------------------------
FROM ${DEBIAN_IMAGE} AS build
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# whisper.cpp v1.9.5. The commit hash pins the source.
ARG WHISPER_COMMIT=d1be6fde11ac6e0407606b4e42fe72d34add8037
ARG GGML_NATIVE=ON
WORKDIR /src
RUN git init -q whisper.cpp \
    && cd whisper.cpp \
    && git fetch -q --depth 1 https://github.com/ggml-org/whisper.cpp.git "$WHISPER_COMMIT" \
    && git checkout -q FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$WHISPER_COMMIT" \
    && cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
         -DWHISPER_BUILD_TESTS=OFF -DGGML_NATIVE="$GGML_NATIVE" \
    && cmake --build build --config Release -j"$(nproc)" --target whisper-server \
    && install -m 0755 build/bin/whisper-server /usr/local/bin/whisper-server

# ggml-base.bin (multilingual, ~142 MB), verified before use.
ARG WHISPER_MODEL_SHA256=60ed5bc3dd14eea856493d334349b405782ddcaf0028d4b5df4088345fba2efe
RUN curl -fsSL --retry 3 -o /ggml-base.bin \
       https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.bin \
    && echo "$WHISPER_MODEL_SHA256  /ggml-base.bin" | sha256sum -c -

# ---- runtime --------------------------------------------------------------
FROM ${DEBIAN_IMAGE}
ARG DEBIAN_FRONTEND=noninteractive
# ffmpeg converts WhatsApp's Opus voice notes to WAV (--convert); libgomp
# runs whisper's threads.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends ffmpeg libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10002 -M -d /nonexistent whisper
COPY --from=build /usr/local/bin/whisper-server /usr/local/bin/whisper-server
COPY --from=build /ggml-base.bin /models/ggml-base.bin
USER whisper
EXPOSE 8080
# Uploaded audio and ffmpeg's conversion live in /tmp, which compose mounts
# as tmpfs (memory only) and removes after each request. The path matches
# the OpenAI-compatible endpoint wpp-mcp calls.
ENTRYPOINT ["whisper-server", "--host", "0.0.0.0", "--port", "8080", \
            "--model", "/models/ggml-base.bin", "--convert", "--tmp-dir", "/tmp", \
            "--inference-path", "/v1/audio/transcriptions", "--language", "auto"]
CMD ["--threads", "2"]
