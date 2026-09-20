#!/bin/sh
# bridge-setup.sh — switch P1 : bridge Linux VLAN-aware (§5.1 aiguillage,
# §5.2 anti-détour L2). Fail-closed : tout port endpoint naît en VLAN 66
# (captif) ; seule la décision LOCALE d'authentification (switchd.sh,
# mabd.sh) le fait sortir du captif — jamais d'attribut VLAN RADIUS
# (§5.3, v1).
#
# VLANs : 10 = serveur (cells/brokers), 20 = endpoints authentifiés,
#         33 = IoT (MAB instrumenté, T20), 66 = captif,
#         77 = remédiation (vérification dégradée, T20),
#         99 = mgmt (switch <-> radius).
#
# Env : IP_BIN / BRIDGE_BIN (défaut : ip / bridge du PATH),
# CAPTIVE_PORTS (ports endpoints en captif — défaut « swp1 swp2 »,
# la topologie T19 ; les tests T20 en ajoutent pour le MAB).
set -eu

IP=${IP_BIN:-ip}
BR=${BRIDGE_BIN:-bridge}
CAPTIVE_PORTS=${CAPTIVE_PORTS:-swp1 swp2}

$IP link add br0 type bridge vlan_filtering 1 vlan_default_pvid 0
$IP link set br0 up
for p in $CAPTIVE_PORTS swp3 swp4 swp5 swp6; do $IP link set $p master br0 up; done

# ports endpoints : PVID 66 (captif) — fail-closed par défaut
for p in $CAPTIVE_PORTS; do
	$BR vlan del vid 1 dev $p 2>/dev/null || true
	$BR vlan add vid 66 pvid untagged dev $p
done

# trunk vers le routeur : VLANs tagués
$BR vlan del vid 1 dev swp3 2>/dev/null || true
for v in 10 20 33 66 77 99; do $BR vlan add vid $v dev swp3; done

# access VLAN 99 (radius) et VLAN 10 (cells — infrastructure, sans auth)
$BR vlan del vid 1 dev swp4 2>/dev/null || true
$BR vlan add vid 99 pvid untagged dev swp4
for p in swp5 swp6; do
	$BR vlan del vid 1 dev $p 2>/dev/null || true
	$BR vlan add vid 10 pvid untagged dev $p
done

# adresse mgmt du switch sur VLAN 99 (pour joindre le RADIUS)
$BR vlan add vid 99 self dev br0
$IP link add link br0 name br0.99 type vlan id 99
$IP link set br0.99 up
$IP addr add 10.99.99.2/24 dev br0.99

echo "bridge-setup: br0 VLAN-aware prêt (captifs $CAPTIVE_PORTS en VLAN 66)"
