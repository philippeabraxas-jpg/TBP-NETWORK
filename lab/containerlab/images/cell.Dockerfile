FROM debian:bookworm-slim
# Cellule P1 : placeholder du broker (socat banner) — le vrai broker vient
# de src/ au fil des tâches ; ici on prouve l'atteignabilité réseau.
RUN apt-get update && apt-get install -y --no-install-recommends \
	socat iproute2 iputils-ping procps \
	&& rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
