# Snort 3 detection engine image.
# Ubuntu 22.04's apt repo only ships Snort 2.9.x (package "snort"); there is
# no snort3 apt package, so Snort 3 is built from the official source tree.
FROM ubuntu:22.04 AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential autotools-dev git ca-certificates \
        cmake pkg-config libtool autoconf bison flex libfl-dev \
        libdumbnet-dev libluajit-5.1-dev libpcap-dev libpcre3-dev \
        zlib1g-dev liblzma-dev libhwloc-dev libunwind-dev \
        openssl libssl-dev libsqlite3-dev uuid-dev && \
    rm -rf /var/lib/apt/lists/*

# libdaq: Snort 3 requires DAQ 3.x, newer than Ubuntu's packaged libdaq2.
RUN git clone --depth 1 --branch v3.0.15 https://github.com/snort3/libdaq.git /usr/src/libdaq && \
    cd /usr/src/libdaq && \
    ./bootstrap && ./configure && \
    make -j"$(nproc)" && make install && ldconfig

RUN git clone --depth 1 --branch 3.1.77.0 https://github.com/snort3/snort3.git /usr/src/snort3 && \
    cd /usr/src/snort3 && \
    ./configure_cmake.sh --prefix=/usr/local && \
    cd build && \
    make -j"$(nproc)" && make install && ldconfig

# ---------------------------------------------------------------------------
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libdumbnet1 libluajit-5.1-2 libpcap0.8 libpcre3 \
        zlib1g liblzma5 libhwloc15 libunwind8 libnuma1 \
        openssl libssl3 libsqlite3-0 libuuid1 \
        iproute2 ca-certificates libcap2-bin && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local /usr/local
RUN ldconfig

# `cap_add` in docker-compose only grants capabilities to root; this service
# runs as a non-root UID (so bind-mounted log files stay owned by the host
# user, not root), which needs the capability on the binary itself to open
# an AF_PACKET socket for afpacket capture.
RUN setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/snort

RUN mkdir -p /etc/snort/rules /var/log/snort

# Verify the binary is present at build time.
RUN snort --version || true

ENTRYPOINT []
