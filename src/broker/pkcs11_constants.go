package broker

// Constantes PKCS#11 v3.0 (Ed25519 / EdDSA) absentes de
// github.com/miekg/pkcs11 (v1.1.x — vendored sur l'en-tête v2.40, antérieur
// à l'ajout d'EdDSA). Valeurs de la spécification OASIS PKCS#11
// Cryptographic Token Interface Current Mechanisms Specification v3.0
// (§2.3.9 « Edwards curves ») — vérifiées empiriquement dans ce dépôt
// contre SoftHSM2 2.6.1 : GetMechanismList/GetMechanismInfo sur le module
// réel confirme 0x1055 → keySize [256,456] generate_key_pair (nom
// pkcs11-tool « EC-EDWARDS-KEY-PAIR-GEN ») et 0x1057 → keySize [256,456]
// sign+verify (nom pkcs11-tool « EDDSA »), exactement les deux mécanismes
// que ce fichier nomme.
const (
	// CkkEcEdwards est CKK_EC_EDWARDS — le type de clé Ed25519/Ed448.
	CkkEcEdwards = 0x00000040
	// CkmEcEdwardsKeyPairGen est CKM_EC_EDWARDS_KEY_PAIR_GEN.
	CkmEcEdwardsKeyPairGen = 0x00001055
	// CkmEddsa est CKM_EDDSA — EdDSA pur (PureEdDSA, pas de prehash) : le
	// mécanisme que coseSignerAdapter attend (il présente déjà le
	// Sig_structure COSE en clair, jamais un digest).
	CkmEddsa = 0x00001057
)

// oidEd25519 est l'OID id-Ed25519 (1.3.101.112, RFC 8410 §3), encodé DER
// (06 03 2B 65 70) — la valeur CKA_EC_PARAMS attendue pour générer une
// paire de clés Ed25519 (par opposition à Ed448).
var oidEd25519 = []byte{0x06, 0x03, 0x2b, 0x65, 0x70}
