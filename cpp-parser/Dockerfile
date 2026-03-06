# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM ubuntu:22.04 AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential cmake ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY CMakeLists.txt .
COPY src/ src/
COPY include/ include/

RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j"$(nproc)"

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libstdc++6 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/build/ssh_parser /usr/local/bin/ssh_parser

# Shared volume mount point for JSON output
RUN mkdir -p /shared

# Default: monitor auth.log and write metrics to /shared/ssh_metrics.json
ENTRYPOINT ["ssh_parser"]
CMD ["--log", "/var/log/auth.log", "--out", "/shared/ssh_metrics.json"]
