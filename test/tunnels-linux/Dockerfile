# One image for the router, the OpenVPN server, and the RiftRoute client.
# Deliberately no procps: the daemon must not need `ps` on Linux.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      openvpn iproute2 iputils-ping openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
