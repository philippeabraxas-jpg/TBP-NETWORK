FROM debian:bookworm-slim
# RADIUS P1 : FreeRADIUS + openssl (PKI du handshake T18 : ca_dev,
# enroll_client). L'arbre raddb stock sert de base à raddb-setup.sh.
RUN apt-get update && apt-get install -y --no-install-recommends \
	freeradius openssl iproute2 iputils-ping procps \
	&& rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
