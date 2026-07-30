package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	dkms "github.com/THCLab/dkms-bindings/bindings/go"
)

var peerKeysB64 = []string{
	"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	"TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=",
}

// A second set of keys anchored together in a single interaction event.
var batchKeysB64 = []string{
	"9k1sMrqZ2hV5oQxk3pF7bYlN0cRtWuGdHjKe8SvXaZI=",
	"L2pNfV6wcE9rTy0bXsQmZ4hK7dRuGvJoAi3lSnPeYcU=",
	"Bz5xQ1oL8vHnKmR3tYcW9fD0aJgSuElP7bXi2ZdNqMk=",
}

const unknownKeyB64 = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="

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

	// Create an identifier (witness threshold 0 keeps the example self-contained).
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

	// anchor each WireGuard public key into the KEL.
	for _, keyB64 := range peerKeysB64 {
		keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			log.Fatalf("decode key %q: %v", keyB64, err)
		}

		ixnEvent, err := identifier.Anchor(keyBytes)
		if err != nil {
			log.Fatalf("Anchor: %v", err)
		}
		ixnSig, err := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, ed25519.Sign(currentPriv, ixnEvent))
		if err != nil {
			log.Fatalf("NewSignature: %v", err)
		}
		if err := identifier.FinalizeAnchor(ixnEvent, ixnSig); err != nil {
			log.Fatalf("FinalizeAnchor: %v", err)
		}
		fmt.Printf("Anchored WireGuard key: %s\n", keyB64)
	}

	// anchor many example
	batchKeys := make([][]byte, 0, len(batchKeysB64))
	for _, keyB64 := range batchKeysB64 {
		keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			log.Fatalf("decode batch key %q: %v", keyB64, err)
		}
		batchKeys = append(batchKeys, keyBytes)
	}

	batchEvent, err := identifier.AnchorMany(batchKeys)
	if err != nil {
		log.Fatalf("AnchorMany: %v", err)
	}
	batchSig, err := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, ed25519.Sign(currentPriv, batchEvent))
	if err != nil {
		log.Fatalf("NewSignature: %v", err)
	}
	if err := identifier.FinalizeAnchor(batchEvent, batchSig); err != nil {
		log.Fatalf("FinalizeAnchor (batch): %v", err)
	}
	fmt.Printf("Anchored %d WireGuard keys in one event\n", len(batchKeys))

	// each batched key is individually verifiable — should be true.
	batched, err := identifier.VerifyAnchor(batchKeys[0])
	if err != nil {
		log.Fatalf("VerifyAnchor (batched): %v", err)
	}
	fmt.Printf("Batched key anchored: %v\n", batched)

	// verify a key we anchored — should be true.
	knownBytes, err := base64.StdEncoding.DecodeString(peerKeysB64[0])
	if err != nil {
		log.Fatalf("decode known key: %v", err)
	}
	known, err := identifier.VerifyAnchor(knownBytes)
	if err != nil {
		log.Fatalf("VerifyAnchor (known): %v", err)
	}
	fmt.Printf("Known key anchored: %v\n", known)

	// verify a key we never anchored — should be false.
	unknownBytes, err := base64.StdEncoding.DecodeString(unknownKeyB64)
	if err != nil {
		log.Fatalf("decode unknown key: %v", err)
	}
	unknown, err := identifier.VerifyAnchor(unknownBytes)
	if err != nil {
		log.Fatalf("VerifyAnchor (unknown): %v", err)
	}
	fmt.Printf("Unknown key anchored: %v\n", unknown)
}
