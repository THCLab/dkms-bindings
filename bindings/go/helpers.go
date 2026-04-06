package dkms

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
)

// Signer signs raw event bytes and returns an encoded signature string.
// Implement this interface to plug in any key management backend.
type Signer interface {
	Sign(data []byte) (string, error)
}

// Ed25519Signer implements Signer using an in-memory ed25519 private key.
type Ed25519Signer struct {
	priv ed25519.PrivateKey
}

// NewEd25519Signer creates a Signer from a raw ed25519 private key.
func NewEd25519Signer(priv ed25519.PrivateKey) *Ed25519Signer {
	return &Ed25519Signer{priv: priv}
}

func (s *Ed25519Signer) Sign(data []byte) (string, error) {
	return NewSignature(SignatureTypeEd25519Sha512, ed25519.Sign(s.priv, data))
}

// InceptAndFinalize creates a new identifier, signs the inception event, and
// finalizes it in one step. If the config includes witnesses, call Publish on
// the returned identifier to collect receipts before using it.
func (c *Controller) InceptAndFinalize(config *InceptionConfig, signer Signer) (*Identifier, error) {
	event, err := c.Incept(config)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(event)
	if err != nil {
		return nil, err
	}
	return c.FinalizeInception(event, sig)
}

// Publish notifies witnesses of the latest KEL event and collects witness
// receipts from the mailbox. Must be called after every Finalize* call that
// anchors a TEL event (InceptRegistry, FinalizeIssue, FinalizeRevoke) and
// before NotifyBackers — the witness receipt is what releases escrowed TEL
// events so they can be forwarded to backers.
func (id *Identifier) Publish(signer Signer) error {
	if err := id.NotifyWitnesses(); err != nil {
		return err
	}
	mailboxQueries, err := id.QueryMailbox()
	if err != nil {
		return err
	}
	var b64List []string
	if err := json.Unmarshal([]byte(mailboxQueries), &b64List); err != nil {
		return err
	}
	for _, b64q := range b64List {
		eventBytes, err := base64.StdEncoding.DecodeString(b64q)
		if err != nil {
			return err
		}
		sig, err := signer.Sign(eventBytes)
		if err != nil {
			return err
		}
		singleJSON, _ := json.Marshal([]string{b64q})
		sigJSON, _ := json.Marshal([]string{sig})
		if err := id.FinalizeQueryMailbox(string(singleJSON), string(sigJSON)); err != nil {
			return err
		}
	}
	return nil
}

// InceptRegistryAndPublish creates the credential registry, publishes the
// anchoring IXN to witnesses, and notifies backers. Returns the registry ID.
func (id *Identifier) InceptRegistryAndPublish(signer Signer) (string, error) {
	registryID, event, err := id.InceptRegistry()
	if err != nil {
		return "", err
	}
	sig, err := signer.Sign(event)
	if err != nil {
		return "", err
	}
	if err := id.FinalizeInceptRegistry(event, sig); err != nil {
		return "", err
	}
	if err := id.Publish(signer); err != nil {
		return "", err
	}
	return registryID, id.NotifyBackers()
}

// IssueAndPublish issues a credential, publishes the anchoring IXN to
// witnesses, and notifies backers. Returns the VC hash (TEL identifier).
func (id *Identifier) IssueAndPublish(vcData []byte, signer Signer) (string, error) {
	vcHash, event, err := id.Issue(vcData)
	if err != nil {
		return "", err
	}
	sig, err := signer.Sign(event)
	if err != nil {
		return "", err
	}
	if err := id.FinalizeIssue(event, sig); err != nil {
		return "", err
	}
	if err := id.Publish(signer); err != nil {
		return "", err
	}
	return vcHash, id.NotifyBackers()
}

// RevokeAndPublish revokes a credential, publishes the anchoring IXN to
// witnesses, and notifies backers.
func (id *Identifier) RevokeAndPublish(vcHash string, signer Signer) error {
	event, err := id.Revoke(vcHash)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(event)
	if err != nil {
		return err
	}
	if err := id.FinalizeRevoke(event, sig); err != nil {
		return err
	}
	if err := id.Publish(signer); err != nil {
		return err
	}
	return id.NotifyBackers()
}

// AddWatcherAndFinalize adds a watcher and finalizes the event in one step.
func (id *Identifier) AddWatcherAndFinalize(watcherOobi string, signer Signer) error {
	event, err := id.AddWatcher(watcherOobi)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(event)
	if err != nil {
		return err
	}
	return id.FinalizeAddWatcher(event, sig)
}

// QueryKELAndFinalize queries the watcher for the KEL of aboutID and
// finalizes all queries in one step. Returns true if the watcher returned
// new events.
func (id *Identifier) QueryKELAndFinalize(aboutID string, signer Signer) (bool, error) {
	queriesJSON, err := id.QueryFullKEL(aboutID)
	if err != nil {
		return false, err
	}
	var b64List []string
	if err := json.Unmarshal([]byte(queriesJSON), &b64List); err != nil {
		return false, err
	}
	sigs := make([]string, len(b64List))
	for i, b64q := range b64List {
		eventBytes, err := base64.StdEncoding.DecodeString(b64q)
		if err != nil {
			return false, err
		}
		sig, err := signer.Sign(eventBytes)
		if err != nil {
			return false, err
		}
		sigs[i] = sig
	}
	sigsJSON, _ := json.Marshal(sigs)
	return id.FinalizeQueryKEL(queriesJSON, string(sigsJSON))
}

// QueryTELAndFinalize queries the watcher for the TEL state of a credential
// and finalizes the query in one step.
func (id *Identifier) QueryTELAndFinalize(registryID, vcHash string, signer Signer) error {
	event, err := id.QueryTEL(registryID, vcHash)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(event)
	if err != nil {
		return err
	}
	return id.FinalizeQueryTEL(event, sig)
}
