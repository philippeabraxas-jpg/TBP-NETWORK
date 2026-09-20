# Campagne red-team P2 — 9 scénarios « Michel » (T28, issue #28)

Métrique non négociable : **zéro action dangereuse non journalisée**.
Chaque scénario doit produire une feuille vérifiable du registre — un
test qui « passe » sans laisser de trace n'a rien prouvé. Les trous
résiduels sont **comptés et déclarés, jamais ignorés** : le verdict
`assert_logged.py` tombe rouge dès qu'un scénario exécuté n'a pas la
couverture de feuilles déclarée, ou qu'un trou n'est pas explicitement
listé dans `run_report.json`.

## Deux harnais (D92, arbitrage revue #28)

| Harnais | Scénarios | Où | Pourquoi |
|---|---|---|---|
| **runner Go** (`runner/`) | S4–S9 | CI (`go test`, `go run`) | attaques in-process contre les **composants réels** (détecteur anti-dribble T23, broker+OPA, contrats T30, promotion T29, validateur T9/T10, quorum T29) avec un **registre tessera réel** — auto-corrélation ChainWatcher incluse |
| **scripts netns** | S1, S2 | lab uniquement | topologie 802.1X/VLAN réelle via `lab/tests/lib_p1_netns.sh` — un sandbox CI ne monte pas de namespaces (`unshare -n` → *Operation not permitted*) |
| **script constat** | S3 | partout | exfiltration USB : prévention **hors réseau**, compensation endpoint — constatée et leafée, jamais maquillée en vert |

Les scénarios lab (S1/S2) réinjectent leur constat en **feuille
d'évidence** (`runner leaf-evidence`, hash salé — le sel reste local,
§6.2) : le vérificateur transversal exige ces feuilles au retour du lab,
et `--require-lab-evidence` rend leur absence bloquante.

## Les 9 scénarios

| # | Scénario | Réf. spec | Mécanisme attaqué | Feuilles attendues | Exécution |
|---|---|---|---|---|---|
| S1 | laptop inconnu | §5.1 | aiguillage NAC : PVID captif 66, mur, bannière TBP-ENROLL | KindTelemetry (évidence lab) | lab netns |
| S2 | SFTP direct | §5.2 | aucun chemin direct client→serveur ; tag 802.1Q forgé meurt au bridge | KindTelemetry (évidence lab) | lab netns |
| S3 | exfiltration USB | §5.2 | prévention hors réseau (USBGuard/GPO/BIOS-IOMMU) | constat (KindTelemetry) | script constat |
| S4 | hotspot / 4G | §5.2 | détection télémétrie anti-dribble T23 (la prévention est incompressible) | KindTelemetryAlert + télémétrie | CI |
| S5 | submersion broker | §7/§8 | DoS alarmé (`OnTrip`), jamais d'acte silencieusement autorisé ; fail-closed OPA down | 2 KindDecision/req (OPA up), 1/req (OPA down — la feuille d'éval porte le refus, pas de double-leaf) | CI |
| S6 | plan menteur | §4.2 | contrat de plan T30 : déviation params refusée (`ErrPlanDeviation`) | 4 KindContract (submit, approve, étape OK, refus déviation) | CI |
| S7 | canari sous partition | §7.4 | fenêtre saine ancrée master, jamais mesurée par le canari (T29) | 3 KindPromotion (promotion, refus ancre indisponible, refus fenêtre expirée) | CI |
| S8 | replay au-delà TTL | §4.3/T10 | jti consommé refusé, jeton expiré refusé (validateur T9) | 3 KindDecision + 1 KindTelemetry (passage en mode fermé, §5.3) | CI |
| S9 | coupure télémétrie | §5.3/§7.5 | action classe W : quorum k-of-n signé et leafé (`QuorumGate.VerifyClassW` au broker), jamais un `systemctl stop` silencieux | 2 KindQuorum (refus insuffisant, quorum accepté) + 3 KindDecision | CI |

## Exécution

```bash
# Campagne CI (S4–S9 + entrées statiques S1/S2/S3)
go run ./tests/p2_redteam/runner run -out /tmp/redteam-out

# Verdict transversal — recalcule tout depuis le rapport + l'export de feuilles
python3 tests/p2_redteam/assert_logged.py --in /tmp/redteam-out

# Lab : S1/S2 (netns requis) — TBP_P2_OUT pointe vers le répertoire de run ;
# chaque script leaf lui-même son constat (leaf-evidence) si go est présent,
# sinon il dépose evidence-SN.json à leafer au retour
sudo TBP_P2_OUT=/tmp/redteam-out bash tests/p2_redteam/scenario_01_unknown_laptop.sh
sudo TBP_P2_OUT=/tmp/redteam-out bash tests/p2_redteam/scenario_02_direct_sftp.sh
go run ./tests/p2_redteam/runner leaf-evidence -out /tmp/redteam-out \
    -scenario S1 -evidence /tmp/redteam-out/evidence-S1.json   # si le script n'a pas pu leafer

# Constat S3 (exécutable partout)
TBP_P2_OUT=/tmp/redteam-out bash tests/p2_redteam/scenario_03_usb_exfil.sh

# Verdict final lab-inclus (bloquant si S1/S2 sans feuille d'évidence)
python3 tests/p2_redteam/assert_logged.py --in /tmp/redteam-out --require-lab-evidence
```

## Tests non vacuoles — 6 mutations léthales (D95)

`go test ./tests/p2_redteam/runner/` prouve que chaque scénario **peut
échouer** : chaque mutation `-mut-*` inverse son scénario (et seulement
le sien) dans `TestMutationsLethal` —

| Mutation | Scénario ciblé | Effet |
|---|---|---|
| `-mut-detector-deaf` | S4 | seuil d'alerte légal mais sourd (1000) — la fuite passe sous le radar |
| `-mut-silent-flood` | S5 | puits qui retourne succès sans écrire — trou de corrélation détecté |
| `-mut-accept-deviation` | S6 | ContractStore mutant qui avale les erreurs `VerifyStep` |
| `-mut-canary-self-measured` | S7 | source d'ancre qui s'auto-atteste ancre **et** fenêtre sous partition |
| `-mut-replay-accept` | S8 | cache anti-rejeu qui déclare tout jti nouveau |
| `-mut-skip-quorum` | S9 | gate qui accepte sans preuve de quorum |

Une mutation qui ne fait pas échouer son scénario est un bug du harnais,
pas une victoire.

## Trous résiduels déclarés (4)

- **S3-usb** — exfiltration USB : prévention hors réseau, compensation
  endpoint ; constatée, non testable au niveau réseau.
- **S4-prevention** — hotspot/4G : canal hors mur, la **prévention** est
  incompressible (§5.2) ; seule la détection télémétrie est testée (S4).
- **physical-access** — accès physique : hors scope réseau, déclaré
  (§13, scénario Michel étendu).
- **S1-S2-lab** — scénarios réseau S1/S2 : exécution netns sur le lab
  (le sandbox CI ne monte pas de namespaces) ; feuilles d'évidence
  exigées au retour.

## Artefacts de run (jamais commités, voir `.gitignore`)

`tests/p2_redteam/out/` ou le `-out` choisi : registre tessera local
(`registry/`), clés de cellule (`cell_log.key` — **ne jamais committer**,
déjà couvert par `*.key`), sel d'évidence (`evidence_salt.hex`, 0600),
`run_report.json`, `leaves_export.json` (scan ChainWatcher vérifié),
`evidence_log.jsonl`. Tout est régénéré à chaque run.
