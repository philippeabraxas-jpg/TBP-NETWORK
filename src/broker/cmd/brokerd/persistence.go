package main

// persistence.go — la restauration, au démarrage, de l'état du miroir (§7.4) et de la file d'arbitrage humain
// (§4.5) (#275 suite). Aucun fichier d'état supplémentaire : l'état est DÉRIVÉ du journal d'enregistrements, c'est-à-
// dire d'événements déjà audités, authentifiés (AEAD) et — pour ce qui accorde un droit — ancrés dans le log signé.
//
//   - une promotion du miroir (« TBPP1 ») et une approbation d'arbitre (« TBAR1 », approve) ne sont restaurées que si
//     leur feuille est dans le log signé (preuve d'inclusion RFC 6962 contre le checkpoint) : un enregistrement forgé
//     avec la clé du journal mais jamais inscrit ne rouvre rien ;
//   - ce qui RETIRE un droit (consommation, refus) s'applique dès que le hash correspond : une consommation dont la
//     feuille n'a pas atteint le checkpoint avant l'arrêt ne doit pas ressusciter l'approbation ;
//   - rien ne prolonge ce que l'ancre signée d'aujourd'hui borne (fenêtre du miroir) ni ce que l'échéance borne
//     (entrées de la file) ;
//   - la présence d'arbitre n'est PAS restaurée : la joignabilité se prouve de nouveau.
//
// Échec de lecture du journal ou du log : alarme, état vide (le comportement antérieur : l'opérateur redépose le
// reçu, les agents renvoient) — jamais un droit accordé sur la foi d'un état que l'on n'a pas pu vérifier. Le journal
// est relu en entier : sur un journal très volumineux, le démarrage s'allonge d'autant.

import (
	"bytes"
	"context"
	"log"

	"golang.org/x/mod/sumdb/note"

	arbiter "github.com/philippeabraxas-jpg/TBP-NETWORK/src/arbiter"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

func restorePersistedState(ctx context.Context, cfg *config, verifier note.Verifier, mirror *mirrorGate, queue *arbiter.Queue, alarm func(string)) {
	if mirror == nil && queue == nil {
		return
	}
	key, err := registry.LoadRecordKey(cfg.auditKeyFile)
	if err != nil {
		log.Printf("brokerd: restauration impossible (clé du journal) : %v", err)
		alarm("persistence-restore-failed")
		return
	}
	recs, err := registry.ReadRecords(cfg.auditRecords, key)
	if err != nil {
		log.Printf("brokerd: restauration impossible (journal illisible) : %v", err)
		alarm("persistence-restore-failed")
		return
	}
	// seuls les enregistrements qui concernent l'état restauré sont vérifiés contre le log
	var relevant []registry.SealedRecord
	for _, r := range recs {
		if r.Leaf.Kind == registry.KindPromotion ||
			(r.Leaf.Kind == registry.KindTelemetry && bytes.HasPrefix(r.Record, []byte("TBAR1"))) {
			relevant = append(relevant, r)
		}
	}
	included := map[string]bool{}
	oks, err := registry.VerifyRecordsInLogDir(ctx, cfg.registryDir, verifier, relevant)
	if err != nil {
		log.Printf("brokerd: log illisible pour la restauration — aucun droit ne sera restauré : %v", err)
		alarm("persistence-restore-failed")
	}
	for i, ok := range oks {
		if ok {
			included[string(relevant[i].LeafData)] = true
		}
	}
	inLog := func(r registry.SealedRecord) bool { return included[string(r.LeafData)] }

	if queue != nil {
		st := queue.Restore(recs, inLog)
		log.Printf("brokerd: arbitrage restauré depuis le journal : %d en attente, %d approuvée(s), %d refusée(s) (%d enregistrement(s) ignoré(s))",
			st.Pending, st.Approved, st.Refused, st.Skipped)
	}
	if mirror != nil {
		if mirror.Restore(recs, inLog) {
			s := mirror.Status()
			log.Printf("brokerd: miroir restauré depuis le journal : cellule %s, époque %d, fenêtre ancrée jusqu'à %s", s.Cell, s.Epoch, s.WindowEnd)
		} else {
			log.Printf("brokerd: aucune promotion de miroir restaurable (reçu à redéposer si besoin)")
		}
	}
}
