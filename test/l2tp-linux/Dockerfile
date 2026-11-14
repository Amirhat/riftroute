# The L2TP/IPsec server (xl2tpd + pppd, strongSwan in transport mode, as most
# Linux L2TP servers run) and the client's container (the distribution's
# charon-systemd), for test/l2tp-linux/run.sh.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends xl2tpd ppp iproute2 iputils-ping procps tcpdump \
    charon-systemd strongswan-swanctl strongswan-pki libstrongswan-standard-plugins \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/run/xl2tpd \
 && printf '[global]\nport = 1701\n\n[lns default]\nip range = 10.88.0.10-10.88.0.20\nlocal ip = 10.88.0.1\nrequire authentication = yes\nname = rr-lns\npppoptfile = /etc/ppp/options.xl2tpd\nlength bit = yes\n' > /etc/xl2tpd/xl2tpd.conf \
 && printf 'alice * s3cret *\n' > /etc/ppp/chap-secrets \
 && printf 'alice * s3cret *\n' > /etc/ppp/pap-secrets \
 && chmod 600 /etc/ppp/chap-secrets /etc/ppp/pap-secrets
