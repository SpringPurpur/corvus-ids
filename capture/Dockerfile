# Lightweight distro, slim variant to conserve disk space
FROM debian:bookworm-slim

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Mount with caching, speeding up rebuilds, prevent concurrent
# corruption with mount sharing, and install necessary packages
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        # C compiler
        gcc \
        # Make build automation
        make \
        # CMake modern build system
        cmake \
        # Netwide Assembler x86
        nasm \
        # Headers for packet capture
        libpcap-dev \
        # Runtime library
        libpcap0.8 \
        # HTTP Client
        curl \
        # Networking tools
        iproute2 \
        # Process tools
        procps \
        # Packet capture CLI
        tcpdump \
        # JSON processor
        jq

WORKDIR /app/capture

CMD ["/bin/bash", "/app/capture/start.sh"]