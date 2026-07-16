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

	dbPath, err := os.MkdirTemp("", "keri-local")
	if err != nil {
		log.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dbPath)

	controller, err := dkms.NewController(dbURL, dbPath, "")
	if err != nil {
		log.Fatalf("NewController: %v", err)
	}
	defer controller.Free()

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
	defer config.Free()
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
	defer identifier.Free()

	id, err := identifier.GetID()
	if err != nil {
		log.Fatalf("GetID: %v", err)
	}
	fmt.Printf("Identifier: %s\n", id)

	// Rotate: pre-committed next key becomes current; commit to a new next key
	newNextPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("GenerateKey: %v", err)
	}
	newNextKey, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, newNextPub)
	if err != nil {
		log.Fatalf("NewPublicKey: %v", err)
	}

	rotConfig := dkms.NewRotationConfig()
	defer rotConfig.Free()
	rotConfig.AddCurrentKey(nextKey)
	rotConfig.AddNextKey(newNextKey)
	rotConfig.SetWitnessThreshold(0)

	rotEvent, err := identifier.Rotate(rotConfig)
	if err != nil {
		log.Fatalf("Rotate: %v", err)
	}
	rotSig, err := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, ed25519.Sign(nextPriv, rotEvent))
	if err != nil {
		log.Fatalf("NewSignature: %v", err)
	}
	if err := identifier.FinalizeRotation(rotEvent, rotSig); err != nil {
		log.Fatalf("FinalizeRotation: %v", err)
	}

	fmt.Println("Key rotation complete (seq: 1)")
}
