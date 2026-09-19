FROM debian:bookworm-slim
# Switch P1 : hostapd en mode wired (authenticator 802.1X) + bridge Linux
# VLAN-aware (aiguillage local — D11 : pas d'image ceos/cvx propriétaire).
RUN apt-get update && apt-get install -y --no-install-recommends \
	hostapd iproute2 iputils-ping procps \
	&& rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
