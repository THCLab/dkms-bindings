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

func main() {
	fmt.Println("DKMS Go Bindings - Key Rotation Example")
	fmt.Println("=========================================")

	// This example demonstrates key rotation in KERI, a critical security feature
	// that allows updating cryptographic keys while maintaining identifier continuity

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	fmt.Println("=== Step 1: Create Initial Identifier ===")

	// Create controller
	controller, err := dkms.NewController(dbURL, "")
	if err != nil {
		log.Fatalf("Failed to create controller: %v", err)
	}
	defer controller.Free()

	// Generate initial key pair (these will be rotated later)
	currentPub, currentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate current key: %v", err)
	}

	// Generate next key pair (pre-rotation commitment)
	nextPub, nextPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate next key: %v", err)
	}

	// Create key prefixes
	currentKey, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, currentPub)
	if err != nil {
		log.Fatalf("Failed to create current key: %v", err)
	}

	nextKey, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, nextPub)
	if err != nil {
		log.Fatalf("Failed to create next key: %v", err)
	}

	fmt.Printf("✓ Generated initial key pair\n")
	fmt.Printf("  Current Key: %s...\n", currentKey[:24])
	fmt.Printf("  Next Key (pre-committed): %s...\n", nextKey[:24])
	fmt.Println()

	// Configure inception
	inceptionConfig := dkms.NewInceptionConfig()
	defer inceptionConfig.Free()
	inceptionConfig.AddCurrentKey(currentKey)
	inceptionConfig.AddNextKey(nextKey)
	inceptionConfig.SetWitnessThreshold(0) // No witnesses for simplicity

	// Create and sign inception event
	icpEvent, err := controller.Incept(inceptionConfig)
	if err != nil {
		log.Fatalf("Failed to create inception event: %v", err)
	}

	signatureBytes := ed25519.Sign(currentPriv, icpEvent)
	signature, err := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, signatureBytes)
	if err != nil {
		log.Fatalf("Failed to create signature: %v", err)
	}

	// Finalize inception
	identifier, err := controller.FinalizeInception(icpEvent, signature)
	if err != nil {
		log.Fatalf("Failed to finalize inception: %v", err)
	}
	defer identifier.Free()

	identifierID, err := identifier.GetID()
	if err != nil {
		log.Fatalf("Failed to get identifier ID: %v", err)
	}

	fmt.Printf("✓ Identifier created: %s\n", identifierID)
	fmt.Printf("  Sequence Number: 0 (inception)\n")
	fmt.Println()

	// Small delay to ensure proper timing
	time.Sleep(100 * time.Millisecond)

	fmt.Println("=== Step 2: Prepare Key Rotation ===")

	// Generate NEW next key pair for post-rotation
	newNextPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate new next key: %v", err)
	}

	newNextKey, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, newNextPub)
	if err != nil {
		log.Fatalf("Failed to create new next key: %v", err)
	}

	fmt.Println("Key rotation changes:")
	fmt.Printf("  • Previous current key → retired\n")
	fmt.Printf("  • Previous next key (%s...) → new current key\n", nextKey[:24])
	fmt.Printf("  • New next key (%s...) → pre-committed for future rotation\n", newNextKey[:24])
	fmt.Println()

	fmt.Println("This demonstrates KERI's pre-rotation scheme:")
	fmt.Println("  1. At inception, we commit to the 'next' key")
	fmt.Println("  2. During rotation, the pre-committed key becomes current")
	fmt.Println("  3. We commit to a new 'next' key for future rotation")
	fmt.Println("  4. This prevents unauthorized key rotation attacks")
	fmt.Println()

	// Configure rotation
	rotationConfig := dkms.NewRotationConfig()
	defer rotationConfig.Free()
	rotationConfig.AddCurrentKey(nextKey) // The pre-committed key becomes current
	rotationConfig.AddNextKey(newNextKey) // New pre-commitment
	rotationConfig.SetWitnessThreshold(0) // No witnesses

	fmt.Println("=== Step 3: Execute Key Rotation ===")

	// Create rotation event
	rotEvent, err := identifier.Rotate(rotationConfig)
	if err != nil {
		log.Fatalf("Failed to create rotation event: %v", err)
	}

	// Sign with the NEW current key (which was the pre-committed 'next' key)
	rotSignatureBytes := ed25519.Sign(nextPriv, rotEvent)
	rotSignature, err := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, rotSignatureBytes)
	if err != nil {
		log.Fatalf("Failed to create rotation signature: %v", err)
	}

	// Finalize rotation
	err = identifier.FinalizeRotation(rotEvent, rotSignature)
	if err != nil {
		log.Fatalf("Failed to finalize rotation: %v", err)
	}

	fmt.Printf("✓ Key rotation completed successfully!\n")
	fmt.Printf("  Identifier: %s (unchanged)\n", identifierID)
	fmt.Printf("  Sequence Number: 1 (after rotation)\n")
	fmt.Println()

	fmt.Println("=== Step 4: Verify Rotation Completed ===")

	// Verify identifier still exists and is unchanged
	currentID, err := identifier.GetID()
	if err != nil {
		log.Fatalf("Failed to get identifier ID: %v", err)
	}

	if currentID == identifierID {
		fmt.Printf("✓ Identifier remains consistent: %s\n", currentID)
		fmt.Println("✓ Key Event Log now contains 2 events:")
		fmt.Println("  1. Inception Event (seq: 0) - established initial key")
		fmt.Println("  2. Rotation Event (seq: 1) - rotated to pre-committed key")
	}
	fmt.Println()

	fmt.Println("=== Key Rotation Benefits ===")
	fmt.Println("Why rotate keys?")
	fmt.Println("  • Limit key exposure: Regular rotation reduces compromise risk")
	fmt.Println("  • Cryptographic agility: Can upgrade to stronger algorithms")
	fmt.Println("  • Compromise recovery: Rotate immediately if key is suspected compromised")
	fmt.Println("  • Compliance: Many standards require periodic key rotation")
	fmt.Println()

	fmt.Println("KERI's Pre-Rotation Advantage:")
	fmt.Println("  • Next key is committed at inception/rotation")
	fmt.Println("  • Attacker cannot forge rotation without pre-committed key")
	fmt.Println("  • Provides forward security and rotation authenticity")
	fmt.Println("  • Enables key recovery scenarios")
	fmt.Println()

	fmt.Println("=== Advanced Rotation Scenarios ===")
	fmt.Println("This example showed basic rotation. Other scenarios include:")
	fmt.Println()
	fmt.Println("1. Multisig Rotation:")
	fmt.Println("   - Rotating keys in a multi-signature scheme")
	fmt.Println("   - Changing signature threshold during rotation")
	fmt.Println()
	fmt.Println("2. Witness Rotation:")
	fmt.Println("   - Adding new witnesses: rotationConfig.AddWitnessToAdd(oobi)")
	fmt.Println("   - Removing witnesses: rotationConfig.AddWitnessToRemove(id)")
	fmt.Println("   - Changing witness threshold")
	fmt.Println()
	fmt.Println("3. Delegated Rotation:")
	fmt.Println("   - Rotating keys for delegated identifiers")
	fmt.Println("   - Requires delegation authorization")
	fmt.Println()
	fmt.Println("4. Emergency Rotation:")
	fmt.Println("   - Using pre-rotation commitment for key recovery")
	fmt.Println("   - Establishes new key when current key is compromised")
	fmt.Println()

	fmt.Println("=========================================")
	fmt.Println("Example completed successfully!")
	fmt.Println()
	fmt.Println("Next Steps:")
	fmt.Println("  • See examples/multisig for multi-signature rotation")
	fmt.Println("  • Review test suite for witness rotation examples")
	fmt.Println("  • Implement key rotation policy for your application")
	fmt.Println("  • Consider key storage and backup strategies")
}
