#ifndef DKMS_GO_H
#define DKMS_GO_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque types
typedef void CController;
typedef void CIdentifier;
typedef void CInceptionConfig;
typedef void CRotationConfig;

// Buffer structure for returning binary data
typedef struct {
    uint8_t* data;
    size_t len;
} CBuffer;

// String array structure
typedef struct {
    char** data;
    size_t len;
} CStringArray;

// Controller functions

/**
 * Creates a new Controller instance.
 * 
 * @param db_path Path to the database directory. Can be NULL for default.
 * @param initial_oobis JSON string of initial OOBI. Can be NULL.
 * @return Pointer to CController or NULL on failure.
 */
CController* controller_new(const char* db_path, const char* initial_oobis);

/**
 * Frees a Controller instance.
 * 
 * @param controller Pointer to the controller to free.
 */
void controller_free(CController* controller);

/**
 * Creates an inception event for a new identifier.
 * 
 * @param controller Pointer to the controller.
 * @param config Pointer to the inception configuration.
 * @param out_len Output parameter for the length of returned buffer.
 * @return Pointer to the inception event data or NULL on failure.
 */
uint8_t* controller_incept(CController* controller, CInceptionConfig* config, size_t* out_len);

/**
 * Finalizes the inception event with a signature.
 * 
 * @param controller Pointer to the controller.
 * @param icp_event Pointer to the inception event data.
 * @param icp_event_len Length of the inception event data.
 * @param signature String representation of the signature.
 * @return Pointer to the created identifier or NULL on failure.
 */
CIdentifier* controller_finalize_inception(CController* controller, const uint8_t* icp_event, size_t icp_event_len, const char* signature);

// InceptionConfiguration functions

/**
 * Creates a new InceptionConfiguration instance.
 * 
 * @return Pointer to CInceptionConfig.
 */
CInceptionConfig* inception_config_new();

/**
 * Frees an InceptionConfiguration instance.
 * 
 * @param config Pointer to the config to free.
 */
void inception_config_free(CInceptionConfig* config);

/**
 * Adds a current public key to the inception configuration.
 * 
 * @param config Pointer to the configuration.
 * @param key String representation of the public key.
 */
void inception_config_add_current_key(CInceptionConfig* config, const char* key);

/**
 * Adds a next public key to the inception configuration.
 * 
 * @param config Pointer to the configuration.
 * @param key String representation of the public key.
 */
void inception_config_add_next_key(CInceptionConfig* config, const char* key);

/**
 * Adds a witness location to the inception configuration.
 * 
 * @param config Pointer to the configuration.
 * @param witness_oobi JSON string of the witness OOBI.
 */
void inception_config_add_witness(CInceptionConfig* config, const char* witness_oobi);

/**
 * Sets the witness threshold.
 * 
 * @param config Pointer to the configuration.
 * @param threshold The witness threshold value.
 */
void inception_config_set_witness_threshold(CInceptionConfig* config, uint32_t threshold);

// RotationConfiguration functions

/**
 * Creates a new RotationConfiguration instance.
 * 
 * @return Pointer to CRotationConfig.
 */
CRotationConfig* rotation_config_new();

/**
 * Frees a RotationConfiguration instance.
 * 
 * @param config Pointer to the config to free.
 */
void rotation_config_free(CRotationConfig* config);

// Identifier functions

/**
 * Frees an Identifier instance.
 * 
 * @param identifier Pointer to the identifier to free.
 */
void identifier_free(CIdentifier* identifier);

/**
 * Gets the identifier string.
 * 
 * @param identifier Pointer to the identifier.
 * @return String representation of the identifier or NULL on failure.
 *         Caller must free with free_string().
 */
char* identifier_get_id(CIdentifier* identifier);

/**
 * Gets the Key Event Log (KEL) for the identifier.
 * 
 * @param identifier Pointer to the identifier.
 * @return String representation of the KEL or NULL on failure.
 *         Caller must free with free_string().
 */
char* identifier_get_kel(CIdentifier* identifier);

/**
 * Creates a rotation event.
 * 
 * @param identifier Pointer to the identifier.
 * @param config Pointer to the rotation configuration.
 * @param out_len Output parameter for the length of returned buffer.
 * @return Pointer to the rotation event data or NULL on failure.
 *         Caller must free with free_buffer().
 */
uint8_t* identifier_rotate(CIdentifier* identifier, CRotationConfig* config, size_t* out_len);

/**
 * Finalizes the rotation event with a signature.
 * 
 * @param identifier Pointer to the identifier.
 * @param rot_event Pointer to the rotation event data.
 * @param rot_event_len Length of the rotation event data.
 * @param signature String representation of the signature.
 * @return 1 on success, 0 on failure.
 */
int identifier_finalize_rotation(CIdentifier* identifier, const uint8_t* rot_event, size_t rot_event_len, const char* signature);

/**
 * Notifies witnesses about the identifier state.
 * 
 * @param identifier Pointer to the identifier.
 * @return 1 on success, 0 on failure.
 */
int identifier_notify_witnesses(CIdentifier* identifier);

/**
 * Signs input data with the identifier.
 * 
 * @param identifier Pointer to the identifier.
 * @param input String to sign.
 * @param signature String representation of the signature.
 * @return Signed stream or NULL on failure. Caller must free with free_string().
 */
char* identifier_sign(CIdentifier* identifier, const char* input, const char* signature);

/**
 * Verifies a signed stream.
 * 
 * @param identifier Pointer to the identifier.
 * @param stream String representation of the signed stream.
 * @return 1 if valid, 0 if invalid, -1 on error.
 */
int identifier_verify(CIdentifier* identifier, const char* stream);

// Verifiable Credential (VC) functions

/**
 * Incepts a registry for issuing verifiable credentials.
 * 
 * @param identifier Pointer to the identifier.
 * @param out_registry_id Output parameter for registry ID string.
 * @param out_len Output parameter for the length of returned buffer.
 * @return Pointer to the registry inception event data or NULL on failure.
 *         Caller must free with free_buffer().
 */
uint8_t* identifier_incept_registry(CIdentifier* identifier, char** out_registry_id, size_t* out_len);

/**
 * Finalizes the registry inception event with a signature.
 * 
 * @param identifier Pointer to the identifier.
 * @param event Pointer to the registry inception event data.
 * @param event_len Length of the event data.
 * @param signature String representation of the signature.
 * @return 1 on success, 0 on failure.
 */
int identifier_finalize_incept_registry(CIdentifier* identifier, const uint8_t* event, size_t event_len, const char* signature);

/**
 * Issues a verifiable credential.
 * 
 * @param identifier Pointer to the identifier.
 * @param vc Pointer to the VC data (typically JSON).
 * @param vc_len Length of the VC data.
 * @param out_vc_hash Output parameter for the VC hash string.
 * @param out_len Output parameter for the length of returned buffer.
 * @return Pointer to the issuance event data or NULL on failure.
 *         Caller must free with free_buffer().
 */
uint8_t* identifier_issue(CIdentifier* identifier, const uint8_t* vc, size_t vc_len, char** out_vc_hash, size_t* out_len);

/**
 * Finalizes the issuance event with a signature.
 * 
 * @param identifier Pointer to the identifier.
 * @param event Pointer to the issuance event data.
 * @param event_len Length of the event data.
 * @param signature String representation of the signature.
 * @return 1 on success, 0 on failure.
 */
int identifier_finalize_issue(CIdentifier* identifier, const uint8_t* event, size_t event_len, const char* signature);

/**
 * Revokes a verifiable credential.
 * 
 * @param identifier Pointer to the identifier.
 * @param vc_hash String representation of the VC hash.
 * @param out_len Output parameter for the length of returned buffer.
 * @return Pointer to the revocation event data or NULL on failure.
 *         Caller must free with free_buffer().
 */
uint8_t* identifier_revoke(CIdentifier* identifier, const char* vc_hash, size_t* out_len);

/**
 * Finalizes the revocation event with a signature.
 * 
 * @param identifier Pointer to the identifier.
 * @param event Pointer to the revocation event data.
 * @param event_len Length of the event data.
 * @param signature String representation of the signature.
 * @return 1 on success, 0 on failure.
 */
int identifier_finalize_revoke(CIdentifier* identifier, const uint8_t* event, size_t event_len, const char* signature);

/**
 * Notifies backers (witnesses for TEL) about credential state changes.
 * 
 * @param identifier Pointer to the identifier.
 * @return 1 on success, 0 on failure.
 */
int identifier_notify_backers(CIdentifier* identifier);

/**
 * Gets the state of a verifiable credential.
 * 
 * @param identifier Pointer to the identifier.
 * @param digest String representation of the VC hash.
 * @return State: 0=Issued, 1=Revoked, 2=NotIssued, -1=Error.
 */
int identifier_vc_state(CIdentifier* identifier, const char* digest);

/**
 * Queries the Transaction Event Log (TEL) for a credential.
 * 
 * @param identifier Pointer to the identifier.
 * @param registry_id String representation of the registry ID.
 * @param vc_id String representation of the VC ID.
 * @param out_len Output parameter for the length of returned buffer.
 * @return Pointer to the TEL query event data or NULL on failure.
 *         Caller must free with free_buffer().
 */
uint8_t* identifier_query_tel(CIdentifier* identifier, const char* registry_id, const char* vc_id, size_t* out_len);

/**
 * Finalizes the TEL query with a signature.
 * 
 * @param identifier Pointer to the identifier.
 * @param event Pointer to the query event data.
 * @param event_len Length of the event data.
 * @param signature String representation of the signature.
 * @return 1 on success, 0 on failure.
 */
int identifier_finalize_query_tel(CIdentifier* identifier, const uint8_t* event, size_t event_len, const char* signature);

/**
 * Gets the registry ID associated with the identifier.
 * 
 * @param identifier Pointer to the identifier.
 * @return String representation of the registry ID or NULL if none.
 *         Caller must free with free_string().
 */
char* identifier_registry_id(CIdentifier* identifier);

// Utility functions

/**
 * Creates a new public key from raw key data.
 * 
 * @param algorithm Algorithm identifier (0=ECDSAsecp256k1, 1=Ed25519, 2=Ed448, 3=X25519, 4=X448).
 * @param key_data Pointer to the raw key data.
 * @param key_len Length of the key data.
 * @return String representation of the public key or NULL on failure.
 *         Caller must free with free_string().
 */
char* public_key_new(uint32_t algorithm, const uint8_t* key_data, size_t key_len);

/**
 * Creates a new signature from raw signature data.
 * 
 * @param algorithm Algorithm identifier (0=Ed25519Sha512, 1=ECDSAsecp256k1Sha256, 2=Ed448).
 * @param sig_data Pointer to the raw signature data.
 * @param sig_len Length of the signature data.
 * @return String representation of the signature or NULL on failure.
 *         Caller must free with free_string().
 */
char* signature_new(uint32_t algorithm, const uint8_t* sig_data, size_t sig_len);

/**
 * Frees a string allocated by the library.
 * 
 * @param s Pointer to the string to free.
 */
void free_string(char* s);

/**
 * Frees a buffer allocated by the library.
 * 
 * @param data Pointer to the buffer data.
 * @param len Length of the buffer.
 */
void free_buffer(uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif // DKMS_GO_H