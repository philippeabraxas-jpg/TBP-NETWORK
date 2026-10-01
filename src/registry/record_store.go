// src/registry/record_store.go — #271
//
// Journal d'enregistrements d'audit : où vit le CLAIR derrière une feuille
// hash-only, et comment un auditeur le rattache à la feuille.
//
// Doctrine (leaf.go, §6.2) : la feuille ne porte que sha256(sel ‖ contenu).
// Le sel et le contenu restent chez le PRODUCTEUR (le démon qui a écrit la
// feuille). Sans journal, « le producteur révèle (sel, contenu) » ne reposait
// sur rien : aucun fichier, aucun format, aucune commande. Ce journal est ce
// fichier.
//
// Un journal par démon, en ajout seul (JSON lignes) :
//
//		{"v":1,"leaf":"<hex Leaf.Marshal()>","nonce":"<b64>","ct":"<b64>"}
//
//	  - leaf  : les octets EXACTS de la feuille inscrite au registre (publics —
//	    la feuille est dans le log) ; sert d'index, sans clé ;
//	  - ct    : AES-256-GCM(clé du journal, nonce, salLen(2) ‖ sel ‖ record) ;
//	  - AAD   : les octets de la feuille. Une entrée déplacée sous une autre
//	    feuille (ou une feuille éditée dans le fichier) ne se déchiffre plus.
//
// Le clair ne quitte JAMAIS la cellule : le registre (et la master chain)
// restent hash-only. La clé du journal est un secret du démon (0600) ; elle ne
// protège que contre la lecture du fichier SEUL — si elle est stockée sur le
// même disque, un attaquant qui prend le disque prend les deux (limite
// documentée dans deploy/audit.md : la mettre en HSM / sur un volume séparé).
//
// Ordre d'écriture (fail-closed, « on audite tout ») : AppendSealed écrit
// l'enregistrement dans le journal (fsync) AVANT d'inscrire la feuille. Si le
// journal refuse, AUCUNE feuille n'est inscrite — pas de feuille dont le clair
// n'existe pas. Le cas inverse (clair écrit, feuille non inscrite) laisse un
// enregistrement ORPHELIN, inoffensif et signalé par la vérification.
package registry

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

const (
	recordStoreVersion = 1
	// RecordKeyLen est la taille de la clé du journal (AES-256).
	RecordKeyLen = 32
	// minSaltLen reprend la règle des producteurs : sel ≥ 16 octets.
	minSaltLen = 16
	// maxRecordEntry borne une ligne du journal (lecture) : un fichier corrompu
	// ou hostile ne doit pas faire allouer sans limite.
	maxRecordEntry = 4 << 20
)

// Erreurs de vérification d'un enregistrement.
var (
	// ErrRecordHashMismatch : sha256(sel ‖ record) ne redonne pas la feuille.
	ErrRecordHashMismatch = errors.New("registre : l'enregistrement ne correspond pas au hash de la feuille")
	// ErrRecordNotInLog : la feuille n'est pas dans le log (enregistrement orphelin).
	ErrRecordNotInLog = errors.New("registre : feuille absente du log (enregistrement orphelin)")
	// ErrRecordUndecryptable : clé erronée, ligne altérée ou feuille éditée.
	ErrRecordUndecryptable = errors.New("registre : entrée du journal indéchiffrable (clé erronée ou entrée altérée)")
)

// SealedRecord est une entrée déchiffrée du journal.
type SealedRecord struct {
	Leaf     Leaf   // la feuille que l'enregistrement explique
	LeafData []byte // octets exacts de la feuille, tels qu'inscrits au log
	Salt     []byte
	Record   []byte
}

type recordLine struct {
	V     int    `json:"v"`
	Leaf  string `json:"leaf"`
	Nonce string `json:"nonce"`
	CT    string `json:"ct"`
}

// GenerateRecordKey écrit une clé de journal neuve (32 octets aléatoires, hex)
// dans path, en 0600, sans jamais écraser un fichier existant.
func GenerateRecordKey(path string) error {
	key := make([]byte, RecordKeyLen)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// LoadRecordKey lit une clé écrite par GenerateRecordKey. Un fichier lisible
// par d'autres comptes est refusé (secret du démon).
func LoadRecordKey(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("clé de journal %s : droits %o trop larges (0600 requis)", path, st.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != RecordKeyLen {
		return nil, fmt.Errorf("clé de journal %s : %d octets hex attendus", path, RecordKeyLen)
	}
	return key, nil
}

func newRecordAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != RecordKeyLen {
		return nil, fmt.Errorf("clé de journal : %d octets requis, %d reçus", RecordKeyLen, len(key))
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// RecordStore est le journal d'enregistrements d'un démon (ajout seul).
type RecordStore struct {
	mu   sync.Mutex
	f    *os.File
	aead cipher.AEAD
}

// OpenRecordStore ouvre (ou crée, en 0600) le journal path avec la clé donnée.
func OpenRecordStore(path string, key []byte) (*RecordStore, error) {
	aead, err := newRecordAEAD(key)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	return &RecordStore{f: f, aead: aead}, nil
}

// Close ferme le journal.
func (s *RecordStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// Put écrit l'enregistrement de la feuille (fsync). Le hash de la feuille doit
// être sha256(salt ‖ record) : on ne journalise pas un clair qui ne l'explique
// pas. L'horodatage est requis (non nul) pour que les octets de la feuille
// journalisés soient ceux que le log recevra.
func (s *RecordStore) Put(leaf Leaf, salt, record []byte) error {
	if len(salt) < minSaltLen {
		return fmt.Errorf("journal : sel ≥ %d octets requis", minSaltLen)
	}
	if leaf.Timestamp == 0 {
		return errors.New("journal : horodatage de la feuille requis")
	}
	if HashPayload(salt, record) != leaf.PayloadHash {
		return ErrRecordHashMismatch
	}
	leafData, err := leaf.Marshal()
	if err != nil {
		return err
	}
	plain := make([]byte, 0, 2+len(salt)+len(record))
	plain = binary.BigEndian.AppendUint16(plain, uint16(len(salt)))
	plain = append(plain, salt...)
	plain = append(plain, record...)
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	line, err := json.Marshal(recordLine{
		V:     recordStoreVersion,
		Leaf:  hex.EncodeToString(leafData),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(s.aead.Seal(nil, nonce, plain, leafData)),
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(append(line, '\n')); err != nil {
		return err
	}
	return s.f.Sync()
}

// AppendSealed journalise le clair PUIS inscrit la feuille : voir l'en-tête du
// fichier. Le sel (≥ 16 octets) et l'horodatage sont requis. Retourne l'index
// de la feuille.
func AppendSealed(ctx context.Context, sink LeafAppender, store *RecordStore, kind byte, cellID string, salt, record []byte, ts int64) (uint64, error) {
	if sink == nil || store == nil {
		return 0, errors.New("journal : couture feuilles et journal requis (on audite tout)")
	}
	leaf := Leaf{Kind: kind, CellID: cellID, PayloadHash: HashPayload(salt, record), Timestamp: ts}
	if err := store.Put(leaf, salt, record); err != nil {
		return 0, fmt.Errorf("journal d'enregistrements : %w (aucune feuille inscrite)", err)
	}
	return sink.Append(ctx, leaf)
}

// AppendLeaf inscrit la feuille (kind, cellID, hash salé de record, ts) ; si
// store != nil, le clair est journalisé d'abord (AppendSealed), sinon c'est la
// feuille nue historique (bibliothèque, tests). Les producteurs de feuilles
// l'appellent au lieu de répéter ce branchement.
func AppendLeaf(ctx context.Context, sink LeafAppender, store *RecordStore, kind byte, cellID string, salt, record []byte, ts int64) (uint64, error) {
	if store != nil {
		return AppendSealed(ctx, sink, store, kind, cellID, salt, record, ts)
	}
	return sink.Append(ctx, Leaf{Kind: kind, CellID: cellID, PayloadHash: HashPayload(salt, record), Timestamp: ts})
}

// OpenRecordStoreFiles ouvre le journal path avec la clé lue dans keyFile
// (LoadRecordKey : 0600 exigé). Un des deux chemins vide ⇒ erreur : les démons
// l'appellent avec leurs variables d'environnement, requises ensemble.
func OpenRecordStoreFiles(path, keyFile string) (*RecordStore, error) {
	if path == "" || keyFile == "" {
		return nil, errors.New("journal d'enregistrements : chemin du journal et fichier de clé requis ensemble")
	}
	key, err := LoadRecordKey(keyFile)
	if err != nil {
		return nil, err
	}
	return OpenRecordStore(path, key)
}

// ReadRecords relit et déchiffre tout le journal. Une ligne altérée, une clé
// erronée ou une feuille éditée fait échouer la lecture (ErrRecordUndecryptable)
// avec le numéro de ligne : un journal partiellement lisible ne passe pas pour
// complet.
func ReadRecords(path string, key []byte) ([]SealedRecord, error) {
	aead, err := newRecordAEAD(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []SealedRecord
	rd := bufio.NewReaderSize(f, 64*1024)
	for n := 1; ; n++ {
		line, err := readBoundedLine(rd)
		if err == io.EOF && len(line) == 0 {
			return out, nil
		}
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("ligne %d : %w", n, err)
		}
		rec, derr := openRecordLine(aead, line)
		if derr != nil {
			return nil, fmt.Errorf("ligne %d : %w", n, derr)
		}
		out = append(out, rec)
		if err == io.EOF {
			return out, nil
		}
	}
}

func readBoundedLine(rd *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, isPrefix, err := rd.ReadLine()
		if err != nil {
			return buf, err
		}
		buf = append(buf, chunk...)
		if len(buf) > maxRecordEntry {
			return nil, errors.New("entrée du journal trop longue")
		}
		if !isPrefix {
			return buf, nil
		}
	}
}

func openRecordLine(aead cipher.AEAD, line []byte) (SealedRecord, error) {
	var rec SealedRecord
	var l recordLine
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return rec, fmt.Errorf("entrée malformée : %w", err)
	}
	if dec.More() {
		return rec, errors.New("entrée malformée : contenu après l'objet")
	}
	if l.V != recordStoreVersion {
		return rec, fmt.Errorf("version d'entrée %d inconnue", l.V)
	}
	leafData, err := hex.DecodeString(l.Leaf)
	if err != nil {
		return rec, fmt.Errorf("feuille illisible : %w", err)
	}
	leaf, err := UnmarshalLeaf(leafData)
	if err != nil {
		return rec, err
	}
	nonce, err := base64.StdEncoding.DecodeString(l.Nonce)
	if err != nil || len(nonce) != aead.NonceSize() {
		return rec, errors.New("nonce invalide")
	}
	ct, err := base64.StdEncoding.DecodeString(l.CT)
	if err != nil {
		return rec, errors.New("texte chiffré illisible")
	}
	plain, err := aead.Open(nil, nonce, ct, leafData)
	if err != nil {
		return rec, ErrRecordUndecryptable
	}
	if len(plain) < 2 {
		return rec, errors.New("clair tronqué")
	}
	sl := int(binary.BigEndian.Uint16(plain))
	if sl < minSaltLen || len(plain) < 2+sl {
		return rec, errors.New("clair malformé (longueur de sel)")
	}
	return SealedRecord{Leaf: leaf, LeafData: leafData, Salt: plain[2 : 2+sl], Record: plain[2+sl:]}, nil
}

// VerifyHash vérifie que (sel, record) redonne le hash porté par la feuille.
func (r SealedRecord) VerifyHash() error {
	got := HashPayload(r.Salt, r.Record)
	if subtle.ConstantTimeCompare(got[:], r.Leaf.PayloadHash[:]) != 1 {
		return ErrRecordHashMismatch
	}
	return nil
}

// VerifyInLog vérifie, avec la seule clé publique du log, que la feuille de
// l'enregistrement est DANS le log : checkpoint signé, recherche de la feuille,
// preuve d'inclusion RFC 6962 contre la racine du checkpoint. Retourne l'index
// de la feuille. fetch lit le log (client.FileFetcher pour un répertoire).
func (r SealedRecord) VerifyInLog(ctx context.Context, fetch LogFetcher, verifier note.Verifier) (uint64, error) {
	if err := r.VerifyHash(); err != nil {
		return 0, err
	}
	raw, err := fetch.ReadCheckpoint(ctx)
	if err != nil {
		return 0, fmt.Errorf("checkpoint : %w", err)
	}
	cp, err := ParseCheckpoint(raw, verifier)
	if err != nil {
		return 0, err
	}
	h := rfc6962.DefaultHasher
	want := h.HashLeaf(r.LeafData)
	hashes, err := client.FetchLeafHashes(ctx, fetch.ReadTile, 0, cp.Size, cp.Size)
	if err != nil {
		return 0, fmt.Errorf("lecture du log : %w", err)
	}
	idx := -1
	for i, lh := range hashes {
		if bytes.Equal(lh, want) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return 0, ErrRecordNotInLog
	}
	pb, err := client.NewProofBuilder(ctx, cp.Size, fetch.ReadTile)
	if err != nil {
		return 0, err
	}
	p, err := pb.InclusionProof(ctx, uint64(idx))
	if err != nil {
		return 0, err
	}
	if err := proof.VerifyInclusion(h, uint64(idx), cp.Size, want, p, cp.Hash); err != nil {
		return 0, fmt.Errorf("preuve d'inclusion rejetée : %w", err)
	}
	return uint64(idx), nil
}

// LogFetcher est la lecture seule d'un log (client.FileFetcher / HTTPFetcher).
type LogFetcher interface {
	ReadCheckpoint(ctx context.Context) ([]byte, error)
	ReadTile(ctx context.Context, level, index uint64, p uint8) ([]byte, error)
}
