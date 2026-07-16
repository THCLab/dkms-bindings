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

	// Generate 3 current and 3 next key pairs
	var currentPrivs []ed25519.PrivateKey
	var currentKeyPrefixes []string
	var nextKeyPrefixes []string

	for i := 0; i < 3; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("GenerateKey: %v", err)
		}
		currentPrivs = append(currentPrivs, priv)
		prefix, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, pub)
		if err != nil {
			log.Fatalf("NewPublicKey: %v", err)
		}
		currentKeyPrefixes = append(currentKeyPrefixes, prefix)
	}

	for i := 0; i < 3; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("GenerateKey: %v", err)
		}
		prefix, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, pub)
		if err != nil {
			log.Fatalf("NewPublicKey: %v", err)
		}
		nextKeyPrefixes = append(nextKeyPrefixes, prefix)
	}

	config := dkms.NewInceptionConfig()
	defer config.Free()
	for _, k := range currentKeyPrefixes {
		config.AddCurrentKey(k)
	}
	for _, k := range nextKeyPrefixes {
		config.AddNextKey(k)
	}
	config.SetWitnessThreshold(0)

	icpEvent, err := controller.Incept(config)
	if err != nil {
		log.Fatalf("Incept: %v", err)
	}
	sig, err := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, ed25519.Sign(currentPrivs[0], icpEvent))
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
	fmt.Printf("Multisig identifier: %s (%d keys)\n", id, len(currentKeyPrefixes))
}
