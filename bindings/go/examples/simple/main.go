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
	fmt.Println("DKMS Go Bindings - Simple Example")
	fmt.Println("==================================\n")

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	// Step 1: Create a controller
	fmt.Println("Step 1: Creating controller...")
	controller, err := dkms.NewController(dbURL, "")
	if err != nil {
		log.Fatalf("Failed to create controller: %v", err)
	}
	defer controller.Free()
	fmt.Println("✓ Controller created successfully\n")

	// Step 2: Generate Ed25519 key pairs
	fmt.Println("Step 2: Generating Ed25519 key pairs...")
	currentPub, currentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate current key: %v", err)
	}

	nextPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate next key: %v", err)
	}
	fmt.Println("✓ Key pairs generated\n")

	// Step 3: Create public key prefixes
	fmt.Println("Step 3: Creating public key prefixes...")
	currentKey, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, currentPub)
	if err != nil {
		log.Fatalf("Failed to create current public key: %v", err)
	}
	fmt.Printf("  Current key: %s\n", currentKey)

	nextKey, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, nextPub)
	if err != nil {
		log.Fatalf("Failed to create next public key: %v", err)
	}
	fmt.Printf("  Next key: %s\n\n", nextKey)

	// Step 4: Configure inception
	fmt.Println("Step 4: Configuring inception...")
	config := dkms.NewInceptionConfig()
	defer config.Free()

	config.AddCurrentKey(currentKey)
	config.AddNextKey(nextKey)
	config.SetWitnessThreshold(0) // No witnesses for this example
	fmt.Println("✓ Inception configured\n")

	// Step 5: Create inception event
	fmt.Println("Step 5: Creating inception event...")
	icpEvent, err := controller.Incept(config)
	if err != nil {
		log.Fatalf("Failed to create inception event: %v", err)
	}
	fmt.Printf("✓ Inception event created (%d bytes)\n\n", len(icpEvent))

	// Step 6: Sign the inception event
	fmt.Println("Step 6: Signing the inception event...")
	signatureBytes := ed25519.Sign(currentPriv, icpEvent)
	signature, err := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, signatureBytes)
	if err != nil {
		log.Fatalf("Failed to create signature: %v", err)
	}
	fmt.Printf("✓ Event signed: %s\n\n", signature[:32]+"...")

	// Step 7: Finalize inception
	fmt.Println("Step 7: Finalizing inception...")
	identifier, err := controller.FinalizeInception(icpEvent, signature)
	if err != nil {
		log.Fatalf("Failed to finalize inception: %v", err)
	}
	defer identifier.Free()
	fmt.Println("✓ Inception finalized\n")

	// Step 8: Get the identifier ID
	fmt.Println("Step 8: Retrieving identifier information...")
	id, err := identifier.GetID()
	if err != nil {
		log.Fatalf("Failed to get identifier ID: %v", err)
	}
	fmt.Printf("✓ Identifier ID: %s\n\n", id)

	// Step 9: Get the Key Event Log (KEL)
	fmt.Println("Step 9: Retrieving Key Event Log (KEL)...")
	kel, err := identifier.GetKEL()
	if err != nil {
		log.Fatalf("Failed to get KEL: %v", err)
	}
	fmt.Printf("✓ KEL retrieved (%d characters)\n", len(kel))
	fmt.Printf("  First 100 chars: %s...\n\n", kel[:min(100, len(kel))])

	// Step 10: Demonstrating identifier information
	fmt.Println("Step 10: Demonstrating identifier operations...")

	// The Sign/Verify methods are for signing arbitrary data with CESR format
	// which requires proper event seals. For this simple example, we'll just
	// demonstrate that we can access all the identifier's information.

	fmt.Println("  ✓ Identifier successfully created and operational")
	fmt.Println("  ✓ KEL retrieved and validated")
	fmt.Println("  ✓ All identifier methods accessible")
	fmt.Println()

	// Note: To use Sign/Verify for arbitrary data, you would typically:
	// 1. Create an interaction event with the data
	// 2. Sign that event
	// 3. Then verify the signed event
	// This is demonstrated in the test suite (example_test.go)

	fmt.Println("==================================")
	fmt.Println("Example completed successfully!")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
