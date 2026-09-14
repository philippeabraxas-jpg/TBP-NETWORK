# Campagne rouge P2 — scénario « Michel » étendu (spec §13)

Métrique non négociable : **zéro action dangereuse non journalisée** — les
trous doivent être comptés, jamais ignorés silencieusement.

## Scénarios à couvrir (extraits de la spec, à détailler en cas de test)

- [ ] Portable inconnu tentant de rejoindre le réseau (§5.1, NAC aiguillage)
- [ ] SFTP direct hors broker (§5.2, "aucun chemin direct client → serveur")
- [ ] Exfiltration par clé USB (§5.2, hardware — hors périmètre réseau,
      compensé par USBGuard/GPO/BIOS-IOMMU)
- [ ] Hotspot / 4G comme canal de contournement (§5.2 — non couvert par
      la prévention, doit être détecté par la télémétrie de ressources)
- [ ] Submersion du broker/registre (§7, §8 — DoS doit être alarmé, jamais
      un acte silencieusement autorisé)
- [ ] Plan mensonger présenté à l'arbitrage humain (§4.2 — vérifier que la
      déviation entre plan approuvé et exécution réelle est bien détectée)
- [ ] Promotion canari sous partition réseau (§7.4 — la fenêtre saine doit
      rester ancrée dans la maîtresse, jamais mesurée par la canari
      elle-même)
- [ ] Rejeu de token au-delà de la fenêtre TTL (§4.3, anti-rejeu jti)
- [ ] Coupure de télémétrie par un admin sous pression (§5.3 — doit exiger
      un quorum, être signée, alarmée, consignée — jamais un simple arrêt
      de service silencieux)

Chaque scénario testé doit produire une feuille dans le registre — un test
qui "réussit" sans laisser de trace vérifiable n'a rien prouvé.
