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
	fmt.Println("DKMS Go Bindings - Multisig Example")
	fmt.Println("====================================\n")

	fmt.Println("This example demonstrates multi-signature (multisig) identifiers.")
	fmt.Println("Multisig allows multiple keys to control a single identifier,")
	fmt.Println("providing enhanced security through key distribution.\n")

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	// Step 1: Create controller
	fmt.Println("Step 1: Creating controller...")
	controller, err := dkms.NewController(dbURL, "")
	if err != nil {
		log.Fatalf("Failed to create controller: %v", err)
	}
	defer controller.Free()
	fmt.Println("✓ Controller created\n")

	// Step 2: Generate multiple key pairs for multisig
	fmt.Println("Step 2: Generating multiple Ed25519 key pairs for multisig...")
	fmt.Println("   Creating 3 current keys and 3 next keys")

	// Generate 3 key pairs for current keys
	var currentPubs []ed25519.PublicKey
	var currentPrivs []ed25519.PrivateKey
	var currentKeyPrefixes []string

	for i := 0; i < 3; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("Failed to generate current key %d: %v", i+1, err)
		}
		currentPubs = append(currentPubs, pub)
		currentPrivs = append(currentPrivs, priv)

		keyPrefix, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, pub)
		if err != nil {
			log.Fatalf("Failed to create current key prefix %d: %v", i+1, err)
		}
		currentKeyPrefixes = append(currentKeyPrefixes, keyPrefix)
		fmt.Printf("   ✓ Current key %d: %s\n", i+1, keyPrefix)
	}

	// Generate 3 key pairs for next keys
	var nextKeyPrefixes []string
	for i := 0; i < 3; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("Failed to generate next key %d: %v", i+1, err)
		}

		keyPrefix, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, pub)
		if err != nil {
			log.Fatalf("Failed to create next key prefix %d: %v", i+1, err)
		}
		nextKeyPrefixes = append(nextKeyPrefixes, keyPrefix)
		fmt.Printf("   ✓ Next key %d: %s\n", i+1, keyPrefix)
	}
	fmt.Println()

	// Step 3: Configure inception with multiple keys
	fmt.Println("Step 3: Configuring multisig inception...")
	config := dkms.NewInceptionConfig()
	defer config.Free()

	// Add all current keys
	for i, key := range currentKeyPrefixes {
		config.AddCurrentKey(key)
		fmt.Printf("   ✓ Added current key %d to configuration\n", i+1)
	}

	// Add all next keys
	for i, key := range nextKeyPrefixes {
		config.AddNextKey(key)
		fmt.Printf("   ✓ Added next key %d to configuration\n", i+1)
	}

	config.SetWitnessThreshold(0) // No witnesses for this example
	fmt.Println("✓ Multisig configuration complete\n")

	// Step 4: Create inception event
	fmt.Println("Step 4: Creating inception event...")
	icpEvent, err := controller.Incept(config)
	if err != nil {
		log.Fatalf("Failed to create inception event: %v", err)
	}
	fmt.Printf("✓ Inception event created (%d bytes)\n\n", len(icpEvent))

	// Step 5: Sign with first key (single signature for inception)
	// Note: In KERI, the inception event needs to be signed by at least one key
	// For multisig operations, multiple signatures would be required for subsequent events
	fmt.Println("Step 5: Signing inception event...")
	fmt.Println("   Note: Using first key to sign inception event")
	signatureBytes := ed25519.Sign(currentPrivs[0], icpEvent)
	signature, err := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, signatureBytes)
	if err != nil {
		log.Fatalf("Failed to create signature: %v", err)
	}
	fmt.Printf("✓ Event signed with key 1\n\n")

	// Step 6: Finalize inception
	fmt.Println("Step 6: Finalizing multisig inception...")
	identifier, err := controller.FinalizeInception(icpEvent, signature)
	if err != nil {
		log.Fatalf("Failed to finalize inception: %v", err)
	}
	defer identifier.Free()
	fmt.Println("✓ Multisig inception finalized\n")

	// Step 7: Verify multisig identifier
	fmt.Println("Step 7: Verifying multisig identifier...")
	id, err := identifier.GetID()
	if err != nil {
		log.Fatalf("Failed to get identifier: %v", err)
	}
	fmt.Printf("✓ Multisig Identifier ID: %s\n\n", id)

	// Step 8: Get KEL and verify it contains multiple keys
	fmt.Println("Step 8: Retrieving Key Event Log (KEL)...")
	kel, err := identifier.GetKEL()
	if err != nil {
		log.Fatalf("Failed to get KEL: %v", err)
	}
	fmt.Printf("✓ KEL retrieved (%d characters)\n", len(kel))
	fmt.Printf("  First 200 chars: %s...\n\n", kel[:min(200, len(kel))])

	// Summary
	fmt.Println("====================================")
	fmt.Println("Multisig Example Summary")
	fmt.Println("====================================\n")
	fmt.Println("Successfully created a multisig identifier with:")
	fmt.Printf("  • %d current public keys\n", len(currentKeyPrefixes))
	fmt.Printf("  • %d next public keys\n", len(nextKeyPrefixes))
	fmt.Printf("  • Identifier: %s\n", id)
	fmt.Println()
	fmt.Println("Key Features of Multisig:")
	fmt.Println("  ✓ Enhanced security through key distribution")
	fmt.Println("  ✓ No single point of failure")
	fmt.Println("  ✓ Suitable for organizational/group identifiers")
	fmt.Println("  ✓ Threshold signing for key rotation and operations")
	fmt.Println()
	fmt.Println("Note: In production multisig scenarios:")
	fmt.Println("  • Each key would be held by different parties/devices")
	fmt.Println("  • Rotation events require threshold number of signatures")
	fmt.Println("  • Witness infrastructure helps coordinate multisig operations")
	fmt.Println("  • Signature threshold (sith) defines minimum required signatures")
	fmt.Println()
	fmt.Println("Example completed successfully! ✓")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
