FROM debian:bookworm-slim
# Routeur Debian du pilote P1 : nftables (le mur), sysctl, socat
# (service d'enrôlement du captif). Charge config/ du dépôt au runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
	nftables iproute2 socat iputils-ping netcat-openbsd procps \
	&& rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
