// Command restart demonstrates resuming a KERI identifier after a simulated
// process restart, instead of incepting a new one.
//
// A Controller only ever hands out an Identifier handle through inception
// (Controller.Incept + Controller.FinalizeInception). That handle lives only
// in process memory — a real restart loses it even though the KEL itself is
// durably stored wherever the Controller points (Postgres here). Without a
// way to reconstruct the handle for an AID that already has a KEL, a
// restarted process would have no option but to incept a second, unrelated
// identifier.
//
// Controller.LoadIdentifier closes that gap: given the AID string alone, it
// reopens the existing KEL under the same Controller (no inception event is
// created or replayed) and returns a handle that is immediately usable for
// further operations — this example uses it to perform a rotation after
// "restarting".
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	dkms "github.com/THCLab/dkms-bindings/bindings/go"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	// A real deployment points dbPath at a persistent volume that survives
	// restarts (it only holds the local mailbox/watcher cache — the KEL
	// itself lives in dbURL's Postgres). Kept for the whole example (not
	// removed between the two "processes" below) to mirror that.
	dbPath, err := os.MkdirTemp("", "keri-local")
	if err != nil {
		log.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dbPath)

	// ---- "process 1": incept a new identifier ----

	controller, err := dkms.NewController(dbURL, dbPath, "")
	if err != nil {
		log.Fatalf("NewController: %v", err)
	}

	currentPub, currentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("GenerateKey: %v", err)
	}
	nextPub, nextPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("GenerateKey: %v", err)
	}

	currentKey, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, currentPub)
	if err != nil {
		log.Fatalf("NewPublicKey: %v", err)
	}
	nextKey, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, nextPub)
	if err != nil {
		log.Fatalf("NewPublicKey: %v", err)
	}

	config := dkms.NewInceptionConfig()
	config.AddCurrentKey(currentKey)
	config.AddNextKey(nextKey)
	config.SetWitnessThreshold(0)

	icpEvent, err := controller.Incept(config)
	if err != nil {
		log.Fatalf("Incept: %v", err)
	}
	sig, err := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, ed25519.Sign(currentPriv, icpEvent))
	if err != nil {
		log.Fatalf("NewSignature: %v", err)
	}
	identifier, err := controller.FinalizeInception(icpEvent, sig)
	if err != nil {
		log.Fatalf("FinalizeInception: %v", err)
	}

	aid, err := identifier.GetID()
	if err != nil {
		log.Fatalf("GetID: %v", err)
	}
	kelBeforeRestart, err := identifier.GetKEL()
	if err != nil {
		log.Fatalf("GetKEL: %v", err)
	}
	fmt.Printf("process 1: incepted %s\n", aid)

	// The seeds must survive the restart too (e.g. loaded back from a KMS or
	// Vault) — LoadIdentifier only reopens the KEL, it never recovers key
	// material. currentPriv/nextPriv below stand in for that.

	// Simulate the process exiting: drop every in-memory handle. A real
	// restart is a fresh process, so there is nothing to defer/Free from here
	// on — this just makes the "no handle survives" starting point explicit.
	identifier.Free()
	controller.Free()

	// ---- "process 2": resume, no re-inception ----

	controller2, err := dkms.NewController(dbURL, dbPath, "")
	if err != nil {
		log.Fatalf("NewController: %v", err)
	}
	defer controller2.Free()

	resumed, err := controller2.LoadIdentifier(aid, "")
	if err != nil {
		log.Fatalf("LoadIdentifier: %v", err)
	}
	defer resumed.Free()

	resumedAID, err := resumed.GetID()
	if err != nil {
		log.Fatalf("GetID: %v", err)
	}
	if resumedAID != aid {
		log.Fatalf("resumed AID %s does not match original %s", resumedAID, aid)
	}

	kelAfterRestart, err := resumed.GetKEL()
	if err != nil {
		log.Fatalf("GetKEL: %v", err)
	}
	if kelAfterRestart != kelBeforeRestart {
		log.Fatal("KEL changed across restart — LoadIdentifier must not create a new event")
	}
	fmt.Printf("process 2: resumed %s, KEL unchanged (%d bytes) — no new icp\n", resumedAID, len(kelAfterRestart))

	// Prove the resumed handle is not just read-only: pre-rotation lets it
	// rotate using the seed kept from inception's "next" key, the same as any
	// long-lived identifier would.
	newNextPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("GenerateKey: %v", err)
	}
	newNextKey, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, newNextPub)
	if err != nil {
		log.Fatalf("NewPublicKey: %v", err)
	}

	rotConfig := dkms.NewRotationConfig()
	rotConfig.AddCurrentKey(nextKey)
	rotConfig.AddNextKey(newNextKey)
	rotConfig.SetWitnessThreshold(0)

	rotEvent, err := resumed.Rotate(rotConfig)
	if err != nil {
		log.Fatalf("Rotate: %v", err)
	}
	rotSig, err := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, ed25519.Sign(nextPriv, rotEvent))
	if err != nil {
		log.Fatalf("NewSignature: %v", err)
	}
	if err := resumed.FinalizeRotation(rotEvent, rotSig); err != nil {
		log.Fatalf("FinalizeRotation: %v", err)
	}

	fmt.Println("process 2: rotation after resume succeeded")
}
