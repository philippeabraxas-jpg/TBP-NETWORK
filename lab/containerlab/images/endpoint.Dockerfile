FROM debian:bookworm-slim
# Endpoint P1 : supplicant 802.1X/EAP-TLS (wpa_supplicant wired) + outils
# de sonde (ping, nc).
RUN apt-get update && apt-get install -y --no-install-recommends \
	wpasupplicant iproute2 iputils-ping netcat-openbsd procps \
	&& rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
