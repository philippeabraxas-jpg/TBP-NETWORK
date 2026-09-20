// latency_pep.js — T27 (issue #29) : forme opérationnelle k6 de la mesure
// « PEP seul » contre un pepd vivant (topologie lab T19, pilotes).
//
// ⚠ Rôle dans le dépôt (D86) : le moteur de mesure CI est le runner Go
// (harness.go — in-process, aucun socket, baseline soustraite). Ce script
// k6 est la forme déployable pour les environnements pilote ; il ne pilote
// pas la CI.
//
// ⚠ Seuils : les thresholds ci-dessous sont les cibles §9.1. Contre un
// pepd adossé au registre tessera POSIX, le chemin COMPLET paie le plancher
// de publication de checkpoint (~150–250 ms, synchrone, fail-closed T9 —
// suivi issue #71) : ces seuils seront rouges tant que #71 n'a pas arbitré
// le modèle de durabilité. Le runner Go mesure le bras « décision » isolé
// (bloquant §9.1) séparément du bras « durabilité » (surveillé).
//
// Jeton : fournir TBP_TOKEN_B64 (COSE_Sign1 base64, classe hors-FIW,
// action read.list). Un jeton réutilisé déclenche l'anti-rejeu T10 à partir
// de la 2ᵉ requête — en mode monitor (§5.3) le refus est journalisé, le
// chemin complet de validation est tout de même exercé et chronométré ;
// pour une mesure au premier passage, minter un jeton frais par VU
// (outillage de menthe : hors scope de ce script).
//
// Usage : k6 run -e TBP_PEP_URL=http://127.0.0.1:8443 -e TBP_TOKEN_B64=... latency_pep.js
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    // tier1 : jeton valide, classe hors-FIW, lecture seule (§9).
    tier1_readonly: {
      executor: 'constant-vus',
      vus: 16,
      duration: '30s',
    },
  },
  thresholds: {
    // Cible §9.1 : latence ajoutée tier1 < 5 ms p95 — ici mesurée sur le
    // chemin complet (à comparer à baseline.js ; rouge tant que #71 est
    // ouvert sur le registre POSIX).
    'http_req_duration{scenario:tier1_readonly}': ['p(95)<5'],
    http_req_failed: ['rate==0'],
  },
};

const PEP = __ENV.TBP_PEP_URL || 'http://127.0.0.1:8443';
const TOKEN = __ENV.TBP_TOKEN_B64 || '';

export default function () {
  const body = JSON.stringify({
    token: TOKEN,
    action: 'read.list',
    resource: 'registry/docs/42',
    epoch: 0,
  });
  const res = http.post(`${PEP}/v1/evaluate`, body, {
    headers: { 'Content-Type': 'application/json' },
  });
  check(res, { 'statut 200': (r) => r.status === 200 });
}

export function handleSummary(data) {
  const p95 = data.metrics.http_req_duration.values['p(95)'];
  console.log(`latency_pep p95 = ${p95.toFixed(3)} ms — à comparer à baseline.js : ajoutée = p95(pep) − p95(baseline)`);
  return { stdout: JSON.stringify(data, null, 2) };
}
