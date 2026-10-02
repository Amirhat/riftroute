# One image for the router, the strongSwan server, and the RiftRoute client:
# the server runs charon with swanctl; the client, the packages RiftRoute's
# install help names for Debian (charon-cmd, kernel-libipsec, OpenSSL's
# crypto, vici). Deliberately no procps: the daemon must not need `ps`.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping openssl ca-certificates \
      charon-cmd libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-standard-plugins strongswan-swanctl \
      strongswan-charon \
    && rm -rf /var/lib/apt/lists/*
