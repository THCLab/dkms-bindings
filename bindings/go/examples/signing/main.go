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
	fmt.Println("DKMS Go Bindings - Data Signing and Verification Example")
	fmt.Println("=========================================================\n")

	// This example demonstrates how to:
	// 1. Create a KERI identifier
	// 2. Sign arbitrary data with the identifier
	// 3. Verify signed data using KERI's cryptographic binding

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	fmt.Println("=== Step 1: Create Signing Identifier ===\n")

	// Create controller
	controller, err := dkms.NewController(dbURL, "")
	if err != nil {
		log.Fatalf("Failed to create controller: %v", err)
	}
	defer controller.Free()

	// Generate keys
	currentPub, currentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate current key: %v", err)
	}

	nextPub, _, err := ed25519.GenerateKey(rand.Reader)
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

	fmt.Printf("✓ Generated key pair\n")
	fmt.Printf("  Current Key: %s...\n", currentKey[:24])
	fmt.Printf("  Next Key: %s...\n", nextKey[:24])
	fmt.Println()

	// Configure inception
	inceptionConfig := dkms.NewInceptionConfig()
	defer inceptionConfig.Free()
	inceptionConfig.AddCurrentKey(currentKey)
	inceptionConfig.AddNextKey(nextKey)
	inceptionConfig.SetWitnessThreshold(0)

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
	fmt.Println()

	fmt.Println("=== Step 2: Sign Data ===\n")

	// Example data to sign
	dataToSign := "This is a message that needs to be signed and verified."
	fmt.Printf("Original Data: %s\n", dataToSign)
	fmt.Println()

	// Sign the data directly with Ed25519
	dataSignatureBytes := ed25519.Sign(currentPriv, []byte(dataToSign))
	dataSignature, err := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, dataSignatureBytes)
	if err != nil {
		log.Fatalf("Failed to create data signature: %v", err)
	}

	// Use the identifier's Sign method to create a CESR-encoded signed message
	signedStream, err := identifier.Sign(dataToSign, dataSignature)
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
	}

	fmt.Printf("✓ Data signed successfully\n")
	fmt.Printf("  Signed Stream Length: %d bytes\n", len(signedStream))
	fmt.Printf("  Signed Stream (first 100 chars): %s...\n", truncate(signedStream, 100))
	fmt.Println()

	fmt.Println("What happened:")
	fmt.Println("  1. Data was signed with the identifier's private key")
	fmt.Println("  2. Signature was encoded in CESR format")
	fmt.Println("  3. Signed stream includes both data and cryptographic proof")
	fmt.Println("  4. Stream is cryptographically bound to the identifier")
	fmt.Println()

	fmt.Println("=== Step 3: Verify Signed Data ===\n")

	// Verify the signed stream
	isValid, err := identifier.Verify(signedStream)
	if err != nil {
		log.Fatalf("Failed to verify signed data: %v", err)
	}

	if isValid {
		fmt.Printf("✅ Signature verification PASSED\n")
		fmt.Println("   The signed data is authentic and has not been tampered with")
	} else {
		fmt.Printf("❌ Signature verification FAILED\n")
		fmt.Println("   The data may have been tampered with or signed by a different key")
	}
	fmt.Println()

	fmt.Println("=== Step 4: Demonstrate Tamper Detection ===\n")

	// Create a tampered version of the signed stream
	tamperedStream := signedStream[:len(signedStream)-10] + "TAMPERED!!"
	fmt.Printf("Created tampered stream (modified last 10 chars)\n")
	fmt.Println()

	// Try to verify the tampered stream
	isTamperedValid, err := identifier.Verify(tamperedStream)
	if err != nil {
		// Verification might error on invalid format
		fmt.Printf("❌ Tampered data verification FAILED (as expected)\n")
		fmt.Printf("   Error: %v\n", err)
	} else if !isTamperedValid {
		fmt.Printf("❌ Tampered data verification FAILED (as expected)\n")
		fmt.Println("   KERI detected the tampering")
	} else {
		fmt.Printf("⚠️  WARNING: Tampered data passed verification (unexpected!)\n")
	}
	fmt.Println()

	fmt.Println("=== Use Cases for KERI Signing ===\n")
	fmt.Println("KERI-based signing provides verifiable signatures for:")
	fmt.Println()
	fmt.Println("1. Document Signing:")
	fmt.Println("   - Legal documents, contracts, agreements")
	fmt.Println("   - Digital signatures with long-term verifiability")
	fmt.Println("   - Key rotation doesn't invalidate old signatures")
	fmt.Println()
	fmt.Println("2. API Authentication:")
	fmt.Println("   - Sign API requests with your identifier")
	fmt.Println("   - Recipients verify using your KEL (Key Event Log)")
	fmt.Println("   - No need for centralized certificate authorities")
	fmt.Println()
	fmt.Println("3. Data Integrity:")
	fmt.Println("   - Sign data at rest or in transit")
	fmt.Println("   - Prove data origin and authenticity")
	fmt.Println("   - Detect any tampering or modifications")
	fmt.Println()
	fmt.Println("4. Code Signing:")
	fmt.Println("   - Sign software releases and updates")
	fmt.Println("   - Verify software provenance")
	fmt.Println("   - Build trust in software supply chain")
	fmt.Println()
	fmt.Println("5. Message Authentication:")
	fmt.Println("   - Secure messaging with cryptographic proof")
	fmt.Println("   - Non-repudiation (sender cannot deny sending)")
	fmt.Println("   - End-to-end verifiable communication")
	fmt.Println()

	fmt.Println("=== KERI Signing Advantages ===\n")
	fmt.Println("Advantages over traditional signing:")
	fmt.Println()
	fmt.Println("✓ Decentralized Trust:")
	fmt.Println("  No certificate authorities or third parties needed")
	fmt.Println()
	fmt.Println("✓ Key Rotation Support:")
	fmt.Println("  Signatures remain valid even after key rotation")
	fmt.Println("  KEL provides historical key state for verification")
	fmt.Println()
	fmt.Println("✓ Self-Certifying:")
	fmt.Println("  Identifier is derived from the initial public key")
	fmt.Println("  No external binding between identity and keys")
	fmt.Println()
	fmt.Println("✓ Cryptographic Agility:")
	fmt.Println("  Support for multiple signature algorithms")
	fmt.Println("  Can migrate to stronger crypto as needed")
	fmt.Println()
	fmt.Println("✓ Verifiable History:")
	fmt.Println("  Complete audit trail of all key operations")
	fmt.Println("  Can verify signatures from any point in time")
	fmt.Println()

	fmt.Println("=== Implementation Notes ===\n")
	fmt.Println("Key Points:")
	fmt.Println()
	fmt.Println("1. Signature Format:")
	fmt.Println("   - Uses CESR (Composable Event Streaming Representation)")
	fmt.Println("   - Self-describing format with type information")
	fmt.Println("   - Includes both data and cryptographic proof")
	fmt.Println()
	fmt.Println("2. Verification Process:")
	fmt.Println("   - Verifier retrieves signer's KEL")
	fmt.Println("   - Determines which key was current at signing time")
	fmt.Println("   - Verifies signature against that key")
	fmt.Println()
	fmt.Println("3. With Witnesses:")
	fmt.Println("   - For production, use witnesses to publish KEL")
	fmt.Println("   - Witnesses provide redundancy and availability")
	fmt.Println("   - Verifiers query witnesses for current KEL state")
	fmt.Println()
	fmt.Println("4. Best Practices:")
	fmt.Println("   - Store private keys securely (HSM, secure enclave)")
	fmt.Println("   - Rotate keys regularly")
	fmt.Println("   - Use sufficient witness threshold")
	fmt.Println("   - Implement key backup and recovery procedures")
	fmt.Println()

	fmt.Println("=========================================================")
	fmt.Println("Example completed successfully!")
	fmt.Println()
	fmt.Println("Next Steps:")
	fmt.Println("  • See examples/rotation for key rotation")
	fmt.Println("  • See examples/multisig for multi-signature signing")
	fmt.Println("  • Review test suite for witness integration")
	fmt.Println("  • Implement signing in your application")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
