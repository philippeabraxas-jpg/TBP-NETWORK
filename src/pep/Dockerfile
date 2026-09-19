# syntax=docker/dockerfile:1

# PEP TBP (T15) — image du démon pepd.
# Build depuis la RACINE du dépôt :
#
#	docker build -f src/pep/Dockerfile -t tbp-pepd .
#
# Run (le registre et la clef note vivent sur un volume ; le sel ne
# quitte jamais la cellule — §6.2) :
#
#	docker run --rm -p 8443:8443 -v tbp-cell:/var/lib/tbp \
#	  -e TBP_CELL_ID=tbp/registry/cell-alpha-01 \
#	  -e TBP_SALT=<hex> -e TBP_KEYRING_FILE=/run/secrets/keyring.json \
#	  -e TBP_POLICY_ID=<hex64> tbp-pepd
#
# Doctrine §5.3 : le démon démarre toujours en mode monitor ; la
# bascule closed est un acte gouverné (POST /v1/mode, quorum), jamais
# une variable d'environnement.

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
	-o /pepd ./src/pep/cmd/pepd
# Répertoire du CellLog pré-créé pour l'uid nonroot (65532) — distroless
# ne permet pas de mkdir au runtime.
RUN install -d -o 65532 -g 65532 /tbp-data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /pepd /pepd
COPY --from=build /tbp-data /var/lib/tbp
# Répertoire du CellLog (montez un volume : feuilles + checkpoints
# Ed25519 + clef note de la cellule).
ENV TBP_REGISTRY_DIR=/var/lib/tbp \
	TBP_LISTEN_ADDR=:8443
VOLUME ["/var/lib/tbp"]
EXPOSE 8443
USER nonroot:nonroot
ENTRYPOINT ["/pepd"]
