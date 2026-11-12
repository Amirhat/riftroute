# The L2TP server (xl2tpd + pppd, as most Linux L2TP servers run) and the
# client's container, for test/l2tp-linux/run.sh.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends xl2tpd ppp iproute2 iputils-ping procps \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/run/xl2tpd \
 && printf '[global]\nport = 1701\n\n[lns default]\nip range = 10.88.0.10-10.88.0.20\nlocal ip = 10.88.0.1\nrequire authentication = yes\nname = rr-lns\npppoptfile = /etc/ppp/options.xl2tpd\nlength bit = yes\n' > /etc/xl2tpd/xl2tpd.conf \
 && printf 'alice * s3cret *\n' > /etc/ppp/chap-secrets \
 && printf 'alice * s3cret *\n' > /etc/ppp/pap-secrets \
 && chmod 600 /etc/ppp/chap-secrets /etc/ppp/pap-secrets
