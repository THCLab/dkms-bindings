package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"

	dkms "github.com/THCLab/dkms-bindings/bindings/go"
)

// VaultSigner implements dkms.Signer using Vault's transit secrets engine.
// The Vault key must be of type "ed25519".
//
// Setup:
//
//	vault secrets enable transit
//	vault write transit/keys/<name> type=ed25519
type VaultSigner struct {
	client  *api.Client
	keyName string
	pubKey  ed25519.PublicKey
}

// NewVaultSigner creates a VaultSigner for the named transit key.
// Reads and caches the public key from Vault on construction.
func NewVaultSigner(addr, token, keyName string) (*VaultSigner, error) {
	cfg := api.DefaultConfig()
	cfg.Address = addr
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}
	client.SetToken(token)

	vs := &VaultSigner{client: client, keyName: keyName}
	if err := vs.loadPublicKey(); err != nil {
		return nil, fmt.Errorf("load public key for %q: %w", keyName, err)
	}
	return vs, nil
}

// PublicKey returns the ed25519 public key for this Vault key.
func (s *VaultSigner) PublicKey() ed25519.PublicKey {
	return s.pubKey
}

// Sign implements dkms.Signer — calls Vault transit to sign data and returns
// a CESR-encoded Ed25519 signature string.
func (s *VaultSigner) Sign(data []byte) (string, error) {
	secret, err := s.client.Logical().Write(
		"transit/sign/"+s.keyName,
		map[string]interface{}{
			"input": base64.StdEncoding.EncodeToString(data),
		},
	)
	if err != nil {
		return "", fmt.Errorf("vault transit sign %q: %w", s.keyName, err)
	}

	raw, ok := secret.Data["signature"].(string)
	if !ok {
		return "", fmt.Errorf("unexpected signature format from vault")
	}

	// Vault returns "vault:v1:<base64-encoded 64-byte signature>"
	b64 := strings.TrimPrefix(raw, "vault:v1:")
	sigBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decode vault signature: %w", err)
	}

	return dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, sigBytes)
}

func (s *VaultSigner) loadPublicKey() error {
	secret, err := s.client.Logical().Read("transit/keys/" + s.keyName)
	if err != nil {
		return err
	}
	if secret == nil {
		return fmt.Errorf("key %q not found — create it with: vault write transit/keys/%s type=ed25519", s.keyName, s.keyName)
	}

	keys, ok := secret.Data["keys"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("unexpected keys structure in vault response")
	}

	// Keys are versioned; pick the latest (last entry in the map)
	var latest map[string]interface{}
	for _, v := range keys {
		latest, _ = v.(map[string]interface{})
	}

	pemStr, ok := latest["public_key"].(string)
	if !ok {
		return fmt.Errorf("public_key missing from vault key data — got: %#v", latest)
	}

	// Try PEM (SubjectPublicKeyInfo) — standard Vault format for ed25519
	if block, _ := pem.Decode([]byte(pemStr)); block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse PKIX public key: %w", err)
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("transit key is not ed25519 (got %T) — set type=ed25519", pub)
		}
		s.pubKey = edPub
		return nil
	}

	// Fallback: raw base64-encoded 32 bytes (some Vault versions / key types)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pemStr))
	if err != nil {
		return fmt.Errorf("public_key is neither PEM nor base64 — raw value: %q", pemStr)
	}
	if len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("unexpected ed25519 public key length %d (want 32) — raw: %q", len(raw), pemStr)
	}
	s.pubKey = ed25519.PublicKey(raw)
	return nil
}
