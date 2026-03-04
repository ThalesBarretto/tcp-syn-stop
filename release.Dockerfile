FROM debian:bookworm

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install all C and packaging dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    libsqlite3-dev \
    liburcu-dev \
    libnftables-dev \
    libcap-dev \
    bpftool \
    nftables \
    pkg-config \
    gcc \
    make \
    dpkg-dev \
    apt-utils \
    curl \
    ca-certificates \
    gzip \
    python3 \
    python3-pytest \
    python3-scapy \
    python3-full \
    iproute2 \
    ethtool \
    socat \
    hping3 \
    musl-tools \
    cppcheck \
    bear \
    clang-tidy \
    build-essential \
    linux-headers-amd64 \
    debhelper \
    lintian \
    && rm -rf /var/lib/apt/lists/*

# Expose kernel + library headers to the musl toolchain (vendored libbpf-sys)
RUN ln -s /usr/include/linux /usr/include/x86_64-linux-musl/linux \
    && ln -s /usr/include/asm-generic /usr/include/x86_64-linux-musl/asm-generic \
    && ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm \
    && ln -s /usr/include/libelf.h /usr/include/x86_64-linux-musl/libelf.h \
    && ln -s /usr/include/gelf.h /usr/include/x86_64-linux-musl/gelf.h \
    && ln -s /usr/include/elfutils /usr/include/x86_64-linux-musl/elfutils \
    && ln -s /usr/include/zlib.h /usr/include/x86_64-linux-musl/zlib.h \
    && ln -s /usr/include/zconf.h /usr/include/x86_64-linux-musl/zconf.h \
    && ln -s /usr/include/nftables /usr/include/x86_64-linux-musl/nftables

# Install Rust and the MUSL target into a world-accessible location so that
# non-root users (release.sh runs --user $(id -u):$(id -g)) can find cargo.
ENV RUSTUP_HOME="/opt/rust/rustup" CARGO_HOME="/opt/rust/cargo"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
ENV PATH="/opt/rust/cargo/bin:${PATH}"

# Pre-install the pinned toolchain so the Docker layer caches it.
# Without this, cargo downloads 1.93.0 on every container run.
COPY rust-toolchain.toml /tmp/rust-toolchain.toml
RUN cd /tmp && rustup show && rm rust-toolchain.toml

RUN cargo install cargo-deny \
    && chmod -R a+rwX /opt/rust

# dpkg-buildpackage writes .deb output to `..`, so the workspace must be
# nested inside a writable parent directory (the container runs as non-root).
RUN mkdir -p /build/workspace && chmod 777 /build
WORKDIR /build/workspace
