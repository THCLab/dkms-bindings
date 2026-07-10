package dkms

/*
#include <stdlib.h>
#include <stdint.h>

// Opaque types
typedef struct CController CController;
typedef struct CIdentifier CIdentifier;
typedef struct CInceptionConfig CInceptionConfig;
typedef struct CRotationConfig CRotationConfig;

// Controller functions
CController* controller_new_postgres(const char* db_url, const char* db_path, const char* initial_oobis);
void controller_free(CController* controller);
uint8_t* controller_incept(CController* controller, CInceptionConfig* config, size_t* out_len);
CIdentifier* controller_finalize_inception(CController* controller, const uint8_t* icp_event, size_t icp_event_len, const char* signature);

// InceptionConfiguration functions
CInceptionConfig* inception_config_new();
void inception_config_free(CInceptionConfig* config);
void inception_config_add_current_key(CInceptionConfig* config, const char* key);
void inception_config_add_next_key(CInceptionConfig* config, const char* key);
void inception_config_add_witness(CInceptionConfig* config, const char* witness_oobi);
void inception_config_set_witness_threshold(CInceptionConfig* config, uint32_t threshold);

// RotationConfiguration functions
CRotationConfig* rotation_config_new();
void rotation_config_free(CRotationConfig* config);
void rotation_config_add_current_key(CRotationConfig* config, const char* key);
void rotation_config_add_next_key(CRotationConfig* config, const char* key);
void rotation_config_add_witness_to_add(CRotationConfig* config, const char* witness_oobi);
void rotation_config_add_witness_to_remove(CRotationConfig* config, const char* witness_id);
void rotation_config_set_witness_threshold(CRotationConfig* config, uint32_t threshold);

// Identifier functions
void identifier_free(CIdentifier* identifier);
char* identifier_get_id(CIdentifier* identifier);
char* identifier_get_kel(CIdentifier* identifier);
uint8_t* identifier_rotate(CIdentifier* identifier, CRotationConfig* config, size_t* out_len);
int identifier_finalize_rotation(CIdentifier* identifier, const uint8_t* rot_event, size_t rot_event_len, const char* signature);
int identifier_notify_witnesses(CIdentifier* identifier);
char* identifier_sign(CIdentifier* identifier, const char* input, const char* signature);
int identifier_verify(CIdentifier* identifier, const char* stream);

// Anchoring functions
uint8_t* identifier_anchor(CIdentifier* identifier, const uint8_t* payload, size_t payload_len, size_t* out_len);
int identifier_finalize_anchor(CIdentifier* identifier, const uint8_t* event, size_t event_len, const char* signature);
int identifier_verify_anchor(CIdentifier* identifier, const uint8_t* payload, size_t payload_len);

// VC (Verifiable Credential) functions
uint8_t* identifier_incept_registry(CIdentifier* identifier, char** out_registry_id, size_t* out_len);
int identifier_finalize_incept_registry(CIdentifier* identifier, const uint8_t* event, size_t event_len, const char* signature);
uint8_t* identifier_issue(CIdentifier* identifier, const uint8_t* vc, size_t vc_len, char** out_vc_hash, size_t* out_len);
int identifier_finalize_issue(CIdentifier* identifier, const uint8_t* event, size_t event_len, const char* signature);
uint8_t* identifier_revoke(CIdentifier* identifier, const char* vc_hash, size_t* out_len);
int identifier_finalize_revoke(CIdentifier* identifier, const uint8_t* event, size_t event_len, const char* signature);
int identifier_notify_backers(CIdentifier* identifier);
int identifier_vc_state(CIdentifier* identifier, const char* digest);
uint8_t* identifier_query_tel(CIdentifier* identifier, const char* registry_id, const char* vc_id, size_t* out_len);
int identifier_finalize_query_tel(CIdentifier* identifier, const uint8_t* event, size_t event_len, const char* signature);
char* identifier_registry_id(CIdentifier* identifier);



// Watcher / KEL query functions
char* identifier_oobi(CIdentifier* identifier);
char* identifier_registry_id_oobi(CIdentifier* identifier);
uint8_t* identifier_add_watcher(CIdentifier* identifier, const char* watcher_oobi, size_t* out_len);
int identifier_finalize_add_watcher(CIdentifier* identifier, const uint8_t* event, size_t event_len, const char* signature);
int identifier_send_oobi_to_watcher(CIdentifier* identifier, const char* oobi);
char* identifier_query_full_kel(CIdentifier* identifier, const char* about_id);
int identifier_finalize_query_kel(CIdentifier* identifier, const char* queries_b64_json, const char* signatures_json);
char* identifier_query_mailbox(CIdentifier* identifier);
int identifier_finalize_query_mailbox(CIdentifier* identifier, const char* queries_b64_json, const char* signatures_json);

// ACDC functions
char* acdc_build(const char* issuer_id, const char* holder_id, const char* registry_id, const char* schema_said, const char* attrs_json, char** out_said);

// Utility functions
char* public_key_new(uint32_t algorithm, const uint8_t* key_data, size_t key_len);
char* signature_new(uint32_t algorithm, const uint8_t* sig_data, size_t sig_len);
void free_string(char* s);
void free_buffer(uint8_t* data, size_t len);
*/
import "C"
import (
	"errors"
	"runtime"
	"unsafe"
)

// KeyType represents the cryptographic key algorithm
type KeyType uint32

const (
	KeyTypeECDSAsecp256k1 KeyType = 0
	KeyTypeEd25519        KeyType = 1
	KeyTypeEd448          KeyType = 2
	KeyTypeX25519         KeyType = 3
	KeyTypeX448           KeyType = 4
)

// SignatureType represents the signature algorithm
type SignatureType uint32

const (
	SignatureTypeEd25519Sha512        SignatureType = 0
	SignatureTypeECDSAsecp256k1Sha256 SignatureType = 1
	SignatureTypeEd448                SignatureType = 2
)

// Controller manages KERI identifiers
type Controller struct {
	ptr *C.CController
}

// Identifier represents a KERI identifier
type Identifier struct {
	ptr *C.CIdentifier
}

// InceptionConfig holds configuration for identifier inception
type InceptionConfig struct {
	ptr *C.CInceptionConfig
}

// RotationConfig holds configuration for key rotation
type RotationConfig struct {
	ptr *C.CRotationConfig
}

func NewController(dbURL string, dbPath string, initialOobis string) (*Controller, error) {
	cDbURL := C.CString(dbURL)
	defer C.free(unsafe.Pointer(cDbURL))

	cDbPath := C.CString(dbPath)
	defer C.free(unsafe.Pointer(cDbPath))

	var cOobis *C.char
	if initialOobis != "" {
		cOobis = C.CString(initialOobis)
		defer C.free(unsafe.Pointer(cOobis))
	}

	ptr := C.controller_new_postgres(cDbURL, cDbPath, cOobis)
	if ptr == nil {
		return nil, errors.New("failed to create postgres controller")
	}

	c := &Controller{ptr: ptr}
	runtime.SetFinalizer(c, (*Controller).Free)
	return c, nil
}

// Free releases the controller resources
func (c *Controller) Free() {
	if c.ptr != nil {
		C.controller_free(c.ptr)
		c.ptr = nil
	}
}

// Incept creates an inception event for a new identifier
func (c *Controller) Incept(config *InceptionConfig) ([]byte, error) {
	if c.ptr == nil {
		return nil, errors.New("controller is nil")
	}
	if config.ptr == nil {
		return nil, errors.New("config is nil")
	}

	var outLen C.size_t
	data := C.controller_incept(c.ptr, config.ptr, &outLen)
	if data == nil {
		return nil, errors.New("failed to create inception event")
	}
	defer C.free_buffer(data, outLen)

	return C.GoBytes(unsafe.Pointer(data), C.int(outLen)), nil
}

// FinalizeInception finalizes the inception event with signature
func (c *Controller) FinalizeInception(icpEvent []byte, signature string) (*Identifier, error) {
	if c.ptr == nil {
		return nil, errors.New("controller is nil")
	}

	cSig := C.CString(signature)
	defer C.free(unsafe.Pointer(cSig))

	ptr := C.controller_finalize_inception(
		c.ptr,
		(*C.uint8_t)(unsafe.Pointer(&icpEvent[0])),
		C.size_t(len(icpEvent)),
		cSig,
	)
	if ptr == nil {
		return nil, errors.New("failed to finalize inception")
	}

	id := &Identifier{ptr: ptr}
	runtime.SetFinalizer(id, (*Identifier).Free)
	return id, nil
}

// NewInceptionConfig creates a new inception configuration
func NewInceptionConfig() *InceptionConfig {
	ic := &InceptionConfig{ptr: C.inception_config_new()}
	runtime.SetFinalizer(ic, (*InceptionConfig).Free)
	return ic
}

// Free releases the inception config resources
func (ic *InceptionConfig) Free() {
	if ic.ptr != nil {
		C.inception_config_free(ic.ptr)
		ic.ptr = nil
	}
}

// AddCurrentKey adds a current public key to the inception configuration
func (ic *InceptionConfig) AddCurrentKey(key string) {
	if ic.ptr != nil {
		cKey := C.CString(key)
		defer C.free(unsafe.Pointer(cKey))
		C.inception_config_add_current_key(ic.ptr, cKey)
	}
}

// AddNextKey adds a next public key to the inception configuration
func (ic *InceptionConfig) AddNextKey(key string) {
	if ic.ptr != nil {
		cKey := C.CString(key)
		defer C.free(unsafe.Pointer(cKey))
		C.inception_config_add_next_key(ic.ptr, cKey)
	}
}

// AddWitness adds a witness location to the inception configuration
func (ic *InceptionConfig) AddWitness(witnessOobi string) {
	if ic.ptr != nil {
		cWitness := C.CString(witnessOobi)
		defer C.free(unsafe.Pointer(cWitness))
		C.inception_config_add_witness(ic.ptr, cWitness)
	}
}

// SetWitnessThreshold sets the witness threshold
func (ic *InceptionConfig) SetWitnessThreshold(threshold uint32) {
	if ic.ptr != nil {
		C.inception_config_set_witness_threshold(ic.ptr, C.uint32_t(threshold))
	}
}

// NewRotationConfig creates a new rotation configuration
func NewRotationConfig() *RotationConfig {
	rc := &RotationConfig{ptr: C.rotation_config_new()}
	runtime.SetFinalizer(rc, (*RotationConfig).Free)
	return rc
}

// Free releases the rotation config resources
func (rc *RotationConfig) Free() {
	if rc.ptr != nil {
		C.rotation_config_free(rc.ptr)
		rc.ptr = nil
	}
}

// AddCurrentKey adds a current public key to the rotation configuration
func (rc *RotationConfig) AddCurrentKey(key string) {
	if rc.ptr != nil {
		cKey := C.CString(key)
		defer C.free(unsafe.Pointer(cKey))
		C.rotation_config_add_current_key(rc.ptr, cKey)
	}
}

// AddNextKey adds a next public key to the rotation configuration
func (rc *RotationConfig) AddNextKey(key string) {
	if rc.ptr != nil {
		cKey := C.CString(key)
		defer C.free(unsafe.Pointer(cKey))
		C.rotation_config_add_next_key(rc.ptr, cKey)
	}
}

// AddWitnessToAdd adds a witness to be added during rotation
func (rc *RotationConfig) AddWitnessToAdd(witnessOobi string) {
	if rc.ptr != nil {
		cWitness := C.CString(witnessOobi)
		defer C.free(unsafe.Pointer(cWitness))
		C.rotation_config_add_witness_to_add(rc.ptr, cWitness)
	}
}

// AddWitnessToRemove adds a witness to be removed during rotation
func (rc *RotationConfig) AddWitnessToRemove(witnessID string) {
	if rc.ptr != nil {
		cWitnessID := C.CString(witnessID)
		defer C.free(unsafe.Pointer(cWitnessID))
		C.rotation_config_add_witness_to_remove(rc.ptr, cWitnessID)
	}
}

// SetWitnessThreshold sets the witness threshold for rotation
func (rc *RotationConfig) SetWitnessThreshold(threshold uint32) {
	if rc.ptr != nil {
		C.rotation_config_set_witness_threshold(rc.ptr, C.uint32_t(threshold))
	}
}

// Free releases the identifier resources
func (id *Identifier) Free() {
	if id.ptr != nil {
		C.identifier_free(id.ptr)
		id.ptr = nil
	}
}

// GetID returns the identifier string
func (id *Identifier) GetID() (string, error) {
	if id.ptr == nil {
		return "", errors.New("identifier is nil")
	}

	cStr := C.identifier_get_id(id.ptr)
	if cStr == nil {
		return "", errors.New("failed to get identifier")
	}

	defer C.free_string(cStr)

	return C.GoString(cStr), nil
}

// GetKEL returns the Key Event Log
func (id *Identifier) GetKEL() (string, error) {
	if id.ptr == nil {
		return "", errors.New("identifier is nil")
	}

	cStr := C.identifier_get_kel(id.ptr)
	if cStr == nil {
		return "", errors.New("failed to get KEL")
	}
	defer C.free_string(cStr)

	return C.GoString(cStr), nil
}

// Rotate creates a rotation event
func (id *Identifier) Rotate(config *RotationConfig) ([]byte, error) {
	if id.ptr == nil {
		return nil, errors.New("identifier is nil")
	}
	if config.ptr == nil {
		return nil, errors.New("config is nil")
	}

	var outLen C.size_t
	data := C.identifier_rotate(id.ptr, config.ptr, &outLen)
	if data == nil {
		return nil, errors.New("failed to create rotation event")
	}
	defer C.free_buffer(data, outLen)

	return C.GoBytes(unsafe.Pointer(data), C.int(outLen)), nil
}

// FinalizeRotation finalizes the rotation event with signature
func (id *Identifier) FinalizeRotation(rotEvent []byte, signature string) error {
	if id.ptr == nil {
		return errors.New("identifier is nil")
	}

	cSig := C.CString(signature)
	defer C.free(unsafe.Pointer(cSig))

	result := C.identifier_finalize_rotation(
		id.ptr,
		(*C.uint8_t)(unsafe.Pointer(&rotEvent[0])),
		C.size_t(len(rotEvent)),
		cSig,
	)
	if result == 0 {
		return errors.New("failed to finalize rotation")
	}

	return nil
}

// NotifyWitnesses notifies witnesses about the identifier state
func (id *Identifier) NotifyWitnesses() error {
	if id.ptr == nil {
		return errors.New("identifier is nil")
	}

	result := C.identifier_notify_witnesses(id.ptr)
	if result == 0 {
		return errors.New("failed to notify witnesses")
	}

	return nil
}

// Sign signs the input data with the identifier
func (id *Identifier) Sign(input string, signature string) (string, error) {
	if id.ptr == nil {
		return "", errors.New("identifier is nil")
	}

	cInput := C.CString(input)
	defer C.free(unsafe.Pointer(cInput))

	cSig := C.CString(signature)
	defer C.free(unsafe.Pointer(cSig))

	cResult := C.identifier_sign(id.ptr, cInput, cSig)
	if cResult == nil {
		return "", errors.New("failed to sign")
	}
	defer C.free_string(cResult)

	return C.GoString(cResult), nil
}

// Verify verifies a signed stream
func (id *Identifier) Verify(stream string) (bool, error) {
	if id.ptr == nil {
		return false, errors.New("identifier is nil")
	}

	cStream := C.CString(stream)
	defer C.free(unsafe.Pointer(cStream))

	result := C.identifier_verify(id.ptr, cStream)
	switch result {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, errors.New("verification error")
	}
}

// Anchor creates an interaction event that anchors the digest of the payload
// into the identifier's KEL. It returns the unsigned event bytes to be signed
// and passed to FinalizeAnchor.
//
// Only the Blake3-256 digest of the payload is committed to the KEL, never the
// payload itself. Verification is byte-exact, so anchor and later verify the
// same canonical bytes (for example, the raw decoded key rather than its
// base64 text).
//
// The event is built from the identifier's current KEL position, so each
// Anchor must be finalized with FinalizeAnchor before the next Anchor call:
// calling Anchor twice before finalizing produces two events with the same
// sequence number, and the second FinalizeAnchor will fail. Anchor one payload
// at a time (Anchor → sign → FinalizeAnchor), as the anchor example does.
func (id *Identifier) Anchor(payload []byte) ([]byte, error) {
	if id.ptr == nil {
		return nil, errors.New("identifier is nil")
	}
	if len(payload) == 0 {
		return nil, errors.New("payload is empty")
	}

	var outLen C.size_t
	data := C.identifier_anchor(
		id.ptr,
		(*C.uint8_t)(unsafe.Pointer(&payload[0])),
		C.size_t(len(payload)),
		&outLen,
	)
	if data == nil {
		return nil, errors.New("failed to create anchor event")
	}
	defer C.free_buffer(data, outLen)

	return C.GoBytes(unsafe.Pointer(data), C.int(outLen)), nil
}

// FinalizeAnchor finalizes the anchor (interaction) event with the signature.
func (id *Identifier) FinalizeAnchor(event []byte, signature string) error {
	if id.ptr == nil {
		return errors.New("identifier is nil")
	}
	if len(event) == 0 {
		return errors.New("event is empty")
	}

	cSig := C.CString(signature)
	defer C.free(unsafe.Pointer(cSig))

	result := C.identifier_finalize_anchor(
		id.ptr,
		(*C.uint8_t)(unsafe.Pointer(&event[0])),
		C.size_t(len(event)),
		cSig,
	)
	if result == 0 {
		return errors.New("failed to finalize anchor")
	}

	return nil
}

// VerifyAnchor reports whether the digest of the payload has been anchored in
// the identifier's KEL. The payload must be byte-identical to the one passed to
// Anchor.
//
// It inspects the accepted (witness-receipted) KEL. For an identifier with a
// non-zero witness threshold, an anchor is only visible after FinalizeAnchor
// followed by NotifyWitnesses and receipt collection (see Publish); before that
// VerifyAnchor returns false because the event is still in escrow. A false
// result thus means "not in the accepted KEL" — for a witnessed identifier that
// can mean "not yet witnessed" rather than "never anchored". A non-nil error
// (rather than false) indicates the KEL could not be read at all.
func (id *Identifier) VerifyAnchor(payload []byte) (bool, error) {
	if id.ptr == nil {
		return false, errors.New("identifier is nil")
	}
	if len(payload) == 0 {
		return false, errors.New("payload is empty")
	}

	result := C.identifier_verify_anchor(
		id.ptr,
		(*C.uint8_t)(unsafe.Pointer(&payload[0])),
		C.size_t(len(payload)),
	)
	switch result {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, errors.New("anchor verification error")
	}
}

// NewPublicKey creates a new public key from raw bytes
func NewPublicKey(algorithm KeyType, keyData []byte) (string, error) {
	if len(keyData) == 0 {
		return "", errors.New("key data is empty")
	}

	cStr := C.public_key_new(
		C.uint32_t(algorithm),
		(*C.uint8_t)(unsafe.Pointer(&keyData[0])),
		C.size_t(len(keyData)),
	)
	if cStr == nil {
		return "", errors.New("failed to create public key")
	}
	defer C.free_string(cStr)

	return C.GoString(cStr), nil
}

// VcState represents the state of a verifiable credential
type VcState int

const (
	VcStateIssued    VcState = 0
	VcStateRevoked   VcState = 1
	VcStateNotIssued VcState = 2
)

// InceptRegistry creates a new credential registry for the identifier
func (id *Identifier) InceptRegistry() (string, []byte, error) {
	if id.ptr == nil {
		return "", nil, errors.New("identifier is nil")
	}

	var cRegistryID *C.char
	var outLen C.size_t
	data := C.identifier_incept_registry(id.ptr, &cRegistryID, &outLen)
	if data == nil {
		return "", nil, errors.New("failed to incept registry")
	}
	defer C.free_buffer(data, outLen)

	registryID := C.GoString(cRegistryID)
	C.free_string(cRegistryID)

	return registryID, C.GoBytes(unsafe.Pointer(data), C.int(outLen)), nil
}

// FinalizeInceptRegistry finalizes the registry inception event with signature
func (id *Identifier) FinalizeInceptRegistry(event []byte, signature string) error {
	if id.ptr == nil {
		return errors.New("identifier is nil")
	}

	cSig := C.CString(signature)
	defer C.free(unsafe.Pointer(cSig))

	result := C.identifier_finalize_incept_registry(
		id.ptr,
		(*C.uint8_t)(unsafe.Pointer(&event[0])),
		C.size_t(len(event)),
		cSig,
	)
	if result == 0 {
		return errors.New("failed to finalize registry inception")
	}

	return nil
}

// Issue creates a verifiable credential issuance event
func (id *Identifier) Issue(vcData []byte) (string, []byte, error) {
	if id.ptr == nil {
		return "", nil, errors.New("identifier is nil")
	}

	var cVcHash *C.char
	var outLen C.size_t
	data := C.identifier_issue(
		id.ptr,
		(*C.uint8_t)(unsafe.Pointer(&vcData[0])),
		C.size_t(len(vcData)),
		&cVcHash,
		&outLen,
	)
	if data == nil {
		return "", nil, errors.New("failed to issue credential")
	}
	defer C.free_buffer(data, outLen)

	vcHash := C.GoString(cVcHash)
	C.free_string(cVcHash)

	return vcHash, C.GoBytes(unsafe.Pointer(data), C.int(outLen)), nil
}

// FinalizeIssue finalizes the credential issuance event with signature
func (id *Identifier) FinalizeIssue(event []byte, signature string) error {
	if id.ptr == nil {
		return errors.New("identifier is nil")
	}

	cSig := C.CString(signature)
	defer C.free(unsafe.Pointer(cSig))

	result := C.identifier_finalize_issue(
		id.ptr,
		(*C.uint8_t)(unsafe.Pointer(&event[0])),
		C.size_t(len(event)),
		cSig,
	)
	if result == 0 {
		return errors.New("failed to finalize credential issuance")
	}

	return nil
}

// Revoke creates a credential revocation event
func (id *Identifier) Revoke(vcHash string) ([]byte, error) {
	if id.ptr == nil {
		return nil, errors.New("identifier is nil")
	}

	cVcHash := C.CString(vcHash)
	defer C.free(unsafe.Pointer(cVcHash))

	var outLen C.size_t
	data := C.identifier_revoke(id.ptr, cVcHash, &outLen)
	if data == nil {
		return nil, errors.New("failed to revoke credential")
	}
	defer C.free_buffer(data, outLen)

	return C.GoBytes(unsafe.Pointer(data), C.int(outLen)), nil
}

// FinalizeRevoke finalizes the credential revocation event with signature
func (id *Identifier) FinalizeRevoke(event []byte, signature string) error {
	if id.ptr == nil {
		return errors.New("identifier is nil")
	}

	cSig := C.CString(signature)
	defer C.free(unsafe.Pointer(cSig))

	result := C.identifier_finalize_revoke(
		id.ptr,
		(*C.uint8_t)(unsafe.Pointer(&event[0])),
		C.size_t(len(event)),
		cSig,
	)
	if result == 0 {
		return errors.New("failed to finalize credential revocation")
	}

	return nil
}

// NotifyBackers notifies backers about the credential registry state
func (id *Identifier) NotifyBackers() error {
	if id.ptr == nil {
		return errors.New("identifier is nil")
	}

	result := C.identifier_notify_backers(id.ptr)
	if result == 0 {
		return errors.New("failed to notify backers")
	}

	return nil
}

// VcState returns the state of a verifiable credential
func (id *Identifier) VcState(digest string) (VcState, error) {
	if id.ptr == nil {
		return -1, errors.New("identifier is nil")
	}

	cDigest := C.CString(digest)
	defer C.free(unsafe.Pointer(cDigest))

	result := C.identifier_vc_state(id.ptr, cDigest)
	if result < 0 {
		return -1, errors.New("failed to get credential state")
	}

	return VcState(result), nil
}

// QueryTEL creates a TEL (Transaction Event Log) query event
func (id *Identifier) QueryTEL(registryID, vcID string) ([]byte, error) {
	if id.ptr == nil {
		return nil, errors.New("identifier is nil")
	}

	cRegistryID := C.CString(registryID)
	defer C.free(unsafe.Pointer(cRegistryID))

	cVcID := C.CString(vcID)
	defer C.free(unsafe.Pointer(cVcID))

	var outLen C.size_t
	data := C.identifier_query_tel(id.ptr, cRegistryID, cVcID, &outLen)
	if data == nil {
		return nil, errors.New("failed to create TEL query")
	}
	defer C.free_buffer(data, outLen)

	return C.GoBytes(unsafe.Pointer(data), C.int(outLen)), nil
}

// FinalizeQueryTEL finalizes the TEL query event with signature
func (id *Identifier) FinalizeQueryTEL(event []byte, signature string) error {
	if id.ptr == nil {
		return errors.New("identifier is nil")
	}

	cSig := C.CString(signature)
	defer C.free(unsafe.Pointer(cSig))

	result := C.identifier_finalize_query_tel(
		id.ptr,
		(*C.uint8_t)(unsafe.Pointer(&event[0])),
		C.size_t(len(event)),
		cSig,
	)
	if result == 0 {
		return errors.New("failed to finalize TEL query")
	}

	return nil
}

// GetRegistryID returns the registry ID for the identifier
func (id *Identifier) GetRegistryID() (string, error) {
	if id.ptr == nil {
		return "", errors.New("identifier is nil")
	}

	cStr := C.identifier_registry_id(id.ptr)
	if cStr == nil {
		return "", errors.New("failed to get registry ID")
	}
	defer C.free_string(cStr)

	return C.GoString(cStr), nil
}

// Oobi returns the identifier's OOBIs as a slice of JSON OOBI strings.
func (id *Identifier) Oobi() ([]string, error) {
	cStr := C.identifier_oobi(id.ptr)
	if cStr == nil {
		return nil, errors.New("failed to get OOBIs")
	}
	defer C.free_string(cStr)
	raw := C.GoString(cStr)
	if raw == "" {
		return []string{}, nil
	}
	result := []string{}
	for _, s := range splitLines(raw) {
		if s != "" {
			result = append(result, s)
		}
	}
	return result, nil
}

// RegistryIdOobi returns the registry's OOBIs as a slice of JSON OOBI strings.
func (id *Identifier) RegistryIdOobi() ([]string, error) {
	cStr := C.identifier_registry_id_oobi(id.ptr)
	if cStr == nil {
		return nil, errors.New("no registry or failed to get registry OOBIs")
	}
	defer C.free_string(cStr)
	raw := C.GoString(cStr)
	if raw == "" {
		return []string{}, nil
	}
	result := []string{}
	for _, s := range splitLines(raw) {
		if s != "" {
			result = append(result, s)
		}
	}
	return result, nil
}

// AddWatcher resolves the watcher's OOBI and returns the add-watcher event bytes.
func (id *Identifier) AddWatcher(watcherOobi string) ([]byte, error) {
	cOobi := C.CString(watcherOobi)
	defer C.free(unsafe.Pointer(cOobi))
	var outLen C.size_t
	data := C.identifier_add_watcher(id.ptr, cOobi, &outLen)
	if data == nil {
		return nil, errors.New("failed to add watcher")
	}
	defer C.free_buffer(data, outLen)
	return C.GoBytes(unsafe.Pointer(data), C.int(outLen)), nil
}

// FinalizeAddWatcher finalizes adding a watcher with the signed event.
func (id *Identifier) FinalizeAddWatcher(event []byte, signature string) error {
	cSig := C.CString(signature)
	defer C.free(unsafe.Pointer(cSig))
	ok := C.identifier_finalize_add_watcher(
		id.ptr,
		(*C.uint8_t)(unsafe.Pointer(&event[0])),
		C.size_t(len(event)),
		cSig,
	)
	if ok == 0 {
		return errors.New("failed to finalize add watcher")
	}
	return nil
}

// SendOobiToWatcher sends an OOBI (location or end-role) to the identifier's watcher.
func (id *Identifier) SendOobiToWatcher(oobi string) error {
	cOobi := C.CString(oobi)
	defer C.free(unsafe.Pointer(cOobi))
	if C.identifier_send_oobi_to_watcher(id.ptr, cOobi) == 0 {
		return errors.New("failed to send OOBI to watcher")
	}
	return nil
}

// QueryFullKEL produces KEL query messages for all watchers about the given identifier.
// Returns a JSON array of base64-encoded query event bytes.
func (id *Identifier) QueryFullKEL(aboutID string) (string, error) {
	cAbout := C.CString(aboutID)
	defer C.free(unsafe.Pointer(cAbout))
	cStr := C.identifier_query_full_kel(id.ptr, cAbout)
	if cStr == nil {
		return "", errors.New("failed to query KEL")
	}
	defer C.free_string(cStr)
	return C.GoString(cStr), nil
}

// FinalizeQueryKEL sends signed KEL queries to watchers.
// queriesB64JSON is a JSON array of base64-encoded query events (from QueryFullKEL).
// signaturesJSON is a JSON array of signature strings, one per query.
// Returns true if the watcher returned new updates.
func (id *Identifier) FinalizeQueryKEL(queriesB64JSON string, signaturesJSON string) (bool, error) {
	cQueries := C.CString(queriesB64JSON)
	defer C.free(unsafe.Pointer(cQueries))
	cSigs := C.CString(signaturesJSON)
	defer C.free(unsafe.Pointer(cSigs))
	result := C.identifier_finalize_query_kel(id.ptr, cQueries, cSigs)
	if result < 0 {
		return false, errors.New("failed to finalize query KEL")
	}
	return result > 0, nil
}

// QueryMailbox queries each witness's mailbox for pending receipts.
// Returns a JSON array of base64-encoded query event bytes, one per witness.
func (id *Identifier) QueryMailbox() (string, error) {
	cStr := C.identifier_query_mailbox(id.ptr)
	if cStr == nil {
		return "", errors.New("failed to query mailbox")
	}
	defer C.free_string(cStr)
	return C.GoString(cStr), nil
}

// FinalizeQueryMailbox processes mailbox receipts (commits witness receipts to key state).
// queriesB64JSON is a JSON array of base64-encoded query events (from QueryMailbox).
// signaturesJSON is a JSON array of signature strings, one per query.
func (id *Identifier) FinalizeQueryMailbox(queriesB64JSON string, signaturesJSON string) error {
	cQueries := C.CString(queriesB64JSON)
	defer C.free(unsafe.Pointer(cQueries))
	cSigs := C.CString(signaturesJSON)
	defer C.free(unsafe.Pointer(cSigs))
	if C.identifier_finalize_query_mailbox(id.ptr, cQueries, cSigs) == 0 {
		return errors.New("failed to finalize query mailbox")
	}
	return nil
}

// splitLines splits a string by newline characters.
func splitLines(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}

// BuildACDCFromJSON constructs a properly SAIDified ACDC attestation from a JSON attributes string.
//
// Parameters:
//   - issuerID:    KERI identifier of the issuer
//   - holderID:    KERI identifier of the credential subject; empty string for untargeted credentials
//   - registryID:  SAID of the credential registry (from InceptRegistry)
//   - schemaSAID:  SAID of the credential schema
//   - attrsJSON:   credential claims as a JSON object string, e.g. `{"name":"Alice"}`
//
// Returns the full ACDC JSON (ready to pass to Issue) and its SAID.
func BuildACDCFromJSON(issuerID, holderID, registryID, schemaSAID, attrsJSON string) (acdcJSON string, said string, err error) {
	cIssuer := C.CString(issuerID)
	defer C.free(unsafe.Pointer(cIssuer))
	cRegistry := C.CString(registryID)
	defer C.free(unsafe.Pointer(cRegistry))
	cSchema := C.CString(schemaSAID)
	defer C.free(unsafe.Pointer(cSchema))
	cAttrs := C.CString(attrsJSON)
	defer C.free(unsafe.Pointer(cAttrs))

	var cHolder *C.char
	if holderID != "" {
		cHolder = C.CString(holderID)
		defer C.free(unsafe.Pointer(cHolder))
	}

	var outSaid *C.char
	cJSON := C.acdc_build(cIssuer, cHolder, cRegistry, cSchema, cAttrs, &outSaid)
	if cJSON == nil {
		return "", "", errors.New("failed to build ACDC")
	}
	defer C.free_string(cJSON)
	if outSaid != nil {
		defer C.free_string(outSaid)
		said = C.GoString(outSaid)
	}
	acdcJSON = C.GoString(cJSON)
	return acdcJSON, said, nil
}

// NewSignature creates a new signature from raw bytes
func NewSignature(algorithm SignatureType, sigData []byte) (string, error) {
	if len(sigData) == 0 {
		return "", errors.New("signature data is empty")
	}

	cStr := C.signature_new(
		C.uint32_t(algorithm),
		(*C.uint8_t)(unsafe.Pointer(&sigData[0])),
		C.size_t(len(sigData)),
	)
	if cStr == nil {
		return "", errors.New("failed to create signature")
	}
	defer C.free_string(cStr)

	return C.GoString(cStr), nil
}
