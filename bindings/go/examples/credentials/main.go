package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
		fmt.Printf("  [retry %d/%d] state=%s, waiting %s...\n", i+1, maxRetries, stateName(st), delay)
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
	fmt.Println("DKMS Go Bindings - Verifiable Credentials Example")
	fmt.Println("===================================================")
	fmt.Println("End-to-end: issuer creates ACDC → verifier independently verifies it")
	fmt.Println()

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

	// -----------------------------------------------------------------------
	fmt.Println("=== Step 1: Create Issuer (with witness) ===")

	issuerController, err := dkms.NewController(dbURL, witnessOobiJSON)
	if err != nil {
		log.Fatalf("issuer controller: %v", err)
	}

	issuerSigner, issuerPub := buildSigner("keri-issuer")
	_, issuerNextPub := buildSigner("keri-issuer-next")

	issuer := inceptIdentifier(issuerController, issuerSigner, issuerPub, issuerNextPub, witnessOobiJSON)

	issuerID, _ := issuer.GetID()
	fmt.Printf("✓ Issuer: %s (inception published + receipts collected)\n", issuerID)

	// -----------------------------------------------------------------------
	fmt.Println("\n=== Step 2: Create Credential Registry ===")

	registryID, err := issuer.InceptRegistryAndPublish(issuerSigner)
	if err != nil {
		log.Fatalf("InceptRegistryAndPublish: %v", err)
	}
	fmt.Printf("✓ Registry: %s (witnesses notified + backers notified)\n", registryID)

	// -----------------------------------------------------------------------
	fmt.Println("\n=== Step 3: Issue ACDC Credential ===")

	attrsJSON := fmt.Sprintf(`{"dt":"%s","name":"Alice","role":"Member"}`, time.Now().UTC().Format(time.RFC3339))
	acdcJSON, acdcSAID, err := dkms.BuildACDCFromJSON(issuerID, issuerID, registryID, schemaSAID, attrsJSON)
	if err != nil {
		log.Fatalf("BuildACDCFromJSON: %v", err)
	}

	var pretty map[string]interface{}
	json.Unmarshal([]byte(acdcJSON), &pretty)
	prettyBytes, _ := json.MarshalIndent(pretty, "  ", "  ")
	fmt.Printf("ACDC:\n  %s\n", string(prettyBytes))
	fmt.Printf("ACDC SAID: %s\n", acdcSAID)

	vcHash, err := issuer.IssueAndPublish([]byte(acdcJSON), issuerSigner)
	if err != nil {
		log.Fatalf("IssueAndPublish: %v", err)
	}
	fmt.Printf("✓ Credential issued (TEL hash: %s, witnesses notified + backers notified)\n", vcHash)

	time.Sleep(2 * time.Second)

	// -----------------------------------------------------------------------
	fmt.Println("\n=== Step 4: Create Verifier (with watcher) ===")

	verifierController, err := dkms.NewController(dbURL, "")
	if err != nil {
		log.Fatalf("verifier controller: %v", err)
	}

	verifierSigner, verifierPub := buildSigner("keri-verifier")
	_, verifierNextPub := buildSigner("keri-verifier-next")

	verifier := inceptIdentifier(verifierController, verifierSigner, verifierPub, verifierNextPub, "")

	verifierID, _ := verifier.GetID()
	fmt.Printf("✓ Verifier: %s\n", verifierID)

	if err := verifier.AddWatcherAndFinalize(watcherOobiJSON, verifierSigner); err != nil {
		log.Fatalf("AddWatcherAndFinalize: %v", err)
	}
	fmt.Println("✓ Watcher added to verifier")

	// -----------------------------------------------------------------------
	fmt.Println("\n=== Step 5: Share Issuer OOBIs with Verifier's Watcher ===")

	issuerOobis, err := issuer.Oobi()
	if err != nil {
		log.Fatalf("Oobi: %v", err)
	}
	for _, oobi := range issuerOobis {
		if err := verifier.SendOobiToWatcher(oobi); err != nil {
			log.Fatalf("SendOobiToWatcher (issuer): %v", err)
		}
	}
	fmt.Printf("✓ Sent %d issuer OOBIs to watcher\n", len(issuerOobis))

	registryOobis, err := issuer.RegistryIdOobi()
	if err != nil {
		log.Fatalf("RegistryIdOobi: %v", err)
	}
	for _, oobi := range registryOobis {
		if err := verifier.SendOobiToWatcher(oobi); err != nil {
			log.Fatalf("SendOobiToWatcher (registry): %v", err)
		}
	}
	fmt.Printf("✓ Sent %d registry OOBIs to watcher\n", len(registryOobis))

	time.Sleep(1 * time.Second)

	// -----------------------------------------------------------------------
	fmt.Println("\n=== Step 6: Verifier Queries Issuer's KEL ===")

	updated, err := verifier.QueryKELAndFinalize(issuerID, verifierSigner)
	if err != nil {
		log.Fatalf("QueryKELAndFinalize: %v", err)
	}
	fmt.Printf("✓ KEL query complete (got updates: %v)\n", updated)

	time.Sleep(1 * time.Second)

	// -----------------------------------------------------------------------
	fmt.Println("\n=== Step 7: Verifier Queries TEL Until Credential Appears as ISSUED ===")

	state := queryTELUntilChanged(verifier, verifierSigner, registryID, vcHash, dkms.VcState(-1), 10)
	fmt.Printf("  Status: %s\n", stateName(state))
	if state == dkms.VcStateIssued {
		fmt.Println("✅ Credential is VALID — independently verified by verifier")
	} else {
		log.Fatalf("unexpected state: %s", stateName(state))
	}

	// -----------------------------------------------------------------------
	fmt.Println("\n=== Step 8: Issuer Revokes Credential ===")

	if err := issuer.RevokeAndPublish(vcHash, issuerSigner); err != nil {
		log.Fatalf("RevokeAndPublish: %v", err)
	}
	fmt.Println("✓ Credential revoked and backers notified")

	// -----------------------------------------------------------------------
	fmt.Println("\n=== Step 9: Verifier Re-queries TEL Until REVOKED ===")

	state2 := queryTELUntilChanged(verifier, verifierSigner, registryID, vcHash, state, 10)
	fmt.Printf("  Status: %s\n", stateName(state2))
	if state2 == dkms.VcStateRevoked {
		fmt.Println("✅ Revocation confirmed — verifier sees credential as REVOKED")
	} else {
		log.Fatalf("expected REVOKED, got: %s", stateName(state2))
	}

	fmt.Println("\n===================================================")
	fmt.Println("End-to-end credential verification complete!")
}
