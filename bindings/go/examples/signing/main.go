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

	controller, err := dkms.NewController(dbURL, "")
	if err != nil {
		log.Fatalf("NewController: %v", err)
	}
	defer controller.Free()

	currentPub, currentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("GenerateKey: %v", err)
	}
	nextPub, _, err := ed25519.GenerateKey(rand.Reader)
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

	// Sign data
	data := "Hello, KERI!"
	dataSig, err := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, ed25519.Sign(currentPriv, []byte(data)))
	if err != nil {
		log.Fatalf("NewSignature: %v", err)
	}
	signedStream, err := identifier.Sign(data, dataSig)
	if err != nil {
		log.Fatalf("Sign: %v", err)
	}
	fmt.Printf("Signed stream: %d bytes\n", len(signedStream))

	// Verify
	valid, err := identifier.Verify(signedStream)
	if err != nil {
		log.Fatalf("Verify: %v", err)
	}
	fmt.Printf("Valid: %v\n", valid)

	// Tamper detection
	tampered := signedStream[:len(signedStream)-10] + "TAMPERED!!"
	_, err = identifier.Verify(tampered)
	if err != nil {
		fmt.Println("Tampered: rejected (as expected)")
	}
}
