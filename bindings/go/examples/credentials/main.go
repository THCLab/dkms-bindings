package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"time"

	dkms "github.com/THCLab/dkms-bindings/bindings/go"
)

const defaultWitnessOobiJSON = `{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://localhost:3232/"}`
const defaultWatcherOobiJSON = `{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://localhost:3236/"}`

// schemaSAID is a placeholder. In production, register your schema and use its real SAID.
const schemaSAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"

func mustGenKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

// buildSigner returns a Signer and its public key.
// When VAULT_ADDR and VAULT_TOKEN are set it uses Vault transit (keyName must
// exist as an ed25519 transit key). Otherwise it generates an ephemeral
// in-memory key.
func buildSigner(keyName string) (dkms.Signer, ed25519.PublicKey) {
	if addr := os.Getenv("VAULT_ADDR"); addr != "" {
		token := os.Getenv("VAULT_TOKEN")
		vs, err := NewVaultSigner(addr, token, keyName)
		if err != nil {
			log.Fatalf("VaultSigner(%s): %v", keyName, err)
		}
		fmt.Printf("  [vault] using transit key %q\n", keyName)
		return vs, vs.PublicKey()
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return dkms.NewEd25519Signer(priv), pub
}

func inceptIdentifier(controller *dkms.Controller, signer dkms.Signer, pub, nextPub ed25519.PublicKey, witnessOobi string) *dkms.Identifier {
	currentKey, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, pub)
	if err != nil {
		log.Fatalf("NewPublicKey: %v", err)
	}
	nextKey, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, nextPub)
	if err != nil {
		log.Fatalf("NewPublicKey next: %v", err)
	}

	cfg := dkms.NewInceptionConfig()
	cfg.AddCurrentKey(currentKey)
	cfg.AddNextKey(nextKey)
	if witnessOobi != "" {
		cfg.AddWitness(witnessOobi)
		cfg.SetWitnessThreshold(1)
	} else {
		cfg.SetWitnessThreshold(0)
	}

	id, err := controller.InceptAndFinalize(cfg, signer)
	if err != nil {
		log.Fatalf("InceptAndFinalize: %v", err)
	}

	if witnessOobi != "" {
		// Publish: notify witness and collect receipts so the identifier exits
		// "partially witnessed" escrow before any TEL operations.
		if err := id.Publish(signer); err != nil {
			log.Fatalf("Publish (inception): %v", err)
		}
	}

	return id
}

// queryTELUntilChanged retries QueryTELAndFinalize until VcState differs
// from cachedState, up to maxRetries attempts (with exponential backoff).
func queryTELUntilChanged(id *dkms.Identifier, signer dkms.Signer, registryID, vcHash string, cachedState dkms.VcState, maxRetries int) dkms.VcState {
	delay := 1 * time.Second
	for i := 0; i < maxRetries; i++ {
		if err := id.QueryTELAndFinalize(registryID, vcHash, signer); err != nil {
			log.Fatalf("QueryTELAndFinalize: %v", err)
		}
		st, _ := id.VcState(vcHash)
		if st != cachedState {
			return st
		}
		fmt.Printf("  [retry %d/%d] waiting %s...\n", i+1, maxRetries, delay)
		time.Sleep(delay)
		if delay < 8*time.Second {
			delay *= 2
		}
	}
	st, _ := id.VcState(vcHash)
	return st
}

func stateName(s dkms.VcState) string {
	switch s {
	case dkms.VcStateIssued:
		return "ISSUED ✅"
	case dkms.VcStateRevoked:
		return "REVOKED ❌"
	default:
		return "NOT_ISSUED"
	}
}

func main() {

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	witnessOobiJSON := os.Getenv("WITNESS_OOBI")
	if witnessOobiJSON == "" {
		witnessOobiJSON = defaultWitnessOobiJSON
	}
	watcherOobiJSON := os.Getenv("WATCHER_OOBI")
	if watcherOobiJSON == "" {
		watcherOobiJSON = defaultWatcherOobiJSON
	}

	issuerDBPath, err := os.MkdirTemp("", "keri-issuer-local")
	if err != nil {
		log.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(issuerDBPath)

	issuerController, err := dkms.NewController(dbURL, issuerDBPath, witnessOobiJSON)
	if err != nil {
		log.Fatalf("issuer controller: %v", err)
	}

	issuerSigner, issuerPub := buildSigner("keri-issuer")
	_, issuerNextPub := buildSigner("keri-issuer-next")

	issuer := inceptIdentifier(issuerController, issuerSigner, issuerPub, issuerNextPub, witnessOobiJSON)

	issuerID, _ := issuer.GetID()
	fmt.Printf("issuer:   %s\n", issuerID)

	registryID, err := issuer.InceptRegistryAndPublish(issuerSigner)
	if err != nil {
		log.Fatalf("InceptRegistryAndPublish: %v", err)
	}
	fmt.Printf("registry: %s\n", registryID)

	attrsJSON := fmt.Sprintf(`{"dt":"%s","name":"Alice","role":"Member"}`, time.Now().UTC().Format(time.RFC3339))
	acdcJSON, acdcSAID, err := dkms.BuildACDCFromJSON(issuerID, issuerID, registryID, schemaSAID, attrsJSON)
	if err != nil {
		log.Fatalf("BuildACDCFromJSON: %v", err)
	}
	fmt.Printf("ACDC SAID: %s\n", acdcSAID)

	vcHash, err := issuer.IssueAndPublish([]byte(acdcJSON), issuerSigner)
	if err != nil {
		log.Fatalf("IssueAndPublish: %v", err)
	}
	fmt.Printf("vc hash:  %s\n", vcHash)

	time.Sleep(2 * time.Second)

	verifierDBPath, err := os.MkdirTemp("", "keri-verifier-local")
	if err != nil {
		log.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(verifierDBPath)

	verifierController, err := dkms.NewController(dbURL, verifierDBPath, "")
	if err != nil {
		log.Fatalf("verifier controller: %v", err)
	}

	verifierSigner, verifierPub := buildSigner("keri-verifier")
	_, verifierNextPub := buildSigner("keri-verifier-next")

	verifier := inceptIdentifier(verifierController, verifierSigner, verifierPub, verifierNextPub, "")

	verifierID, _ := verifier.GetID()
	fmt.Printf("verifier: %s\n", verifierID)

	if err := verifier.AddWatcherAndFinalize(watcherOobiJSON, verifierSigner); err != nil {
		log.Fatalf("AddWatcherAndFinalize: %v", err)
	}

	issuerOobis, err := issuer.Oobi()
	if err != nil {
		log.Fatalf("Oobi: %v", err)
	}
	for _, oobi := range issuerOobis {
		if err := verifier.SendOobiToWatcher(oobi); err != nil {
			log.Fatalf("SendOobiToWatcher (issuer): %v", err)
		}
	}

	registryOobis, err := issuer.RegistryIdOobi()
	if err != nil {
		log.Fatalf("RegistryIdOobi: %v", err)
	}
	for _, oobi := range registryOobis {
		if err := verifier.SendOobiToWatcher(oobi); err != nil {
			log.Fatalf("SendOobiToWatcher (registry): %v", err)
		}
	}

	time.Sleep(1 * time.Second)

	if _, err := verifier.QueryKELAndFinalize(issuerID, verifierSigner); err != nil {
		log.Fatalf("QueryKELAndFinalize: %v", err)
	}

	time.Sleep(1 * time.Second)

	state := queryTELUntilChanged(verifier, verifierSigner, registryID, vcHash, dkms.VcState(-1), 10)
	if state != dkms.VcStateIssued {
		log.Fatalf("unexpected state: %s", stateName(state))
	}
	fmt.Printf("status:   %s\n", stateName(state))

	if err := issuer.RevokeAndPublish(vcHash, issuerSigner); err != nil {
		log.Fatalf("RevokeAndPublish: %v", err)
	}

	state2 := queryTELUntilChanged(verifier, verifierSigner, registryID, vcHash, state, 10)
	if state2 != dkms.VcStateRevoked {
		log.Fatalf("expected REVOKED, got: %s", stateName(state2))
	}
	fmt.Printf("status:   %s\n", stateName(state2))
}
