// baseline.js — T27 (issue #29) : mesure SANS le PEP (soustraction, §9.1).
// Cible /healthz de pepd : même serveur HTTP, même transport, aucune
// validation — la différence p95(latency_pep.js) − p95(baseline.js) est la
// latence AJOUTÉE par le PEP (chemin complet, registre inclus — voir le
// commentaire de seuils de latency_pep.js et l'issue #71).
//
// Usage : k6 run -e TBP_PEP_URL=http://127.0.0.1:8443 baseline.js
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    baseline: {
      executor: 'constant-vus',
      vus: 16,
      duration: '30s',
    },
  },
  // Pas de seuil absolu : la baseline EST la référence soustraite.
  thresholds: {
    http_req_failed: ['rate==0'],
  },
};

const PEP = __ENV.TBP_PEP_URL || 'http://127.0.0.1:8443';

export default function () {
  const res = http.get(`${PEP}/healthz`);
  check(res, { 'statut 200': (r) => r.status === 200 });
}

export function handleSummary(data) {
  const p95 = data.metrics.http_req_duration.values['p(95)'];
  console.log(`baseline p95 = ${p95.toFixed(3)} ms — référence sans PEP (à soustraire de latency_pep.js)`);
  return { stdout: JSON.stringify(data, null, 2) };
}
