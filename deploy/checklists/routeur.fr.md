# Checklist de recette — routeur (T35, issue #61)

_English version: [routeur.md](routeur.md)._

À cocher sur la machine, dans l'ordre. Une case rouge = STOP.

## §5.1 Segmentation

- [ ] Les six VLANs existent et sont `UP` (10 serveur, 20 auth, 33 IoT/MAB,
      66 captif, 77 remédiation, 99 mgmt — plan à adapter au pilote).
- [ ] `nft list table inet tbp_p1` montre les murs et leurs compteurs
      (fichier de référence `config/nftables/router-p1.nft`, à adapter).
- [ ] Les compteurs bougent quand le trafic traverse (visibilité avant
      filtrage — même doctrine que monitor avant closed, §5.3).

## §3/§12 Authentification

- [ ] EAP-TLS uniquement (pas de PEAP/MSCHAP), PKI du pilote (§3).
- [ ] `freeradius -XC` vert ; RADIUS n'écoute que sur le VLAN auth.
- [ ] Aucun certificat/clé n'est commité (`config/freeradius/certs/` est
      gitignoré ; la PKI se génère pour CE déploiement).

## Fail-closed au switch

- [ ] VLAN par défaut = captif (66) : un inconnu n'est JAMAIS admis.
- [ ] Certificat révoqué ou OCSP/CRL injoignable = remédiation (77),
      observé avec un certificat de test révoqué.
- [ ] Les trois issues (admis → 10, inconnu → 66, révoqué → 77) ont été
      OBSERVÉES en lab, pas supposées (router-debian.md étape 7).

## MAB (équipements sans supplicant 802.1X)

- [ ] Le MAB est confiné au VLAN IoT dédié (33) — jamais sur un VLAN de
      confiance.
- [ ] Chaque admission MAB est journalisée et comptée : un équipement MAB
      **jamais silencieux** — canal instrumenté, pas une porte dérobée.
- [ ] Un équipement MAB inconnu tombe en captif comme tout inconnu.
