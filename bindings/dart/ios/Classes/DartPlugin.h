#import <Flutter/Flutter.h>

@interface DartPlugin : NSObject<FlutterPlugin>
@end
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct wire_uint_8_list {
  uint8_t *ptr;
  int32_t len;
} wire_uint_8_list;

typedef struct wire_Config {
  struct wire_uint_8_list *initial_oobis;
} wire_Config;

typedef struct wire_PublicKey {
  int32_t algorithm;
  struct wire_uint_8_list *key;
} wire_PublicKey;

typedef struct wire_list_public_key {
  struct wire_PublicKey *ptr;
  int32_t len;
} wire_list_public_key;

typedef struct wire_StringList {
  struct wire_uint_8_list **ptr;
  int32_t len;
} wire_StringList;

typedef struct wire_Signature {
  int32_t algorithm;
  struct wire_uint_8_list *key;
} wire_Signature;

typedef struct wire_Controller {
  struct wire_uint_8_list *identifier;
} wire_Controller;

typedef struct WireSyncReturnStruct {
  uint8_t *ptr;
  int32_t len;
  bool success;
} WireSyncReturnStruct;

typedef int64_t DartPort;

typedef bool (*DartPostCObjectFnType)(DartPort port_id, void *message);

void wire_with_initial_oobis(int64_t port_,
                             struct wire_Config *config,
                             struct wire_uint_8_list *oobis_json);

void wire_init_kel(int64_t port_,
                   struct wire_uint_8_list *input_app_dir,
                   struct wire_Config *optional_configs);

void wire_incept(int64_t port_,
                 struct wire_list_public_key *public_keys,
                 struct wire_list_public_key *next_pub_keys,
                 struct wire_StringList *witnesses,
                 uint64_t witness_threshold);

void wire_finalize_inception(int64_t port_,
                             struct wire_uint_8_list *event,
                             struct wire_Signature *signature);

void wire_rotate(int64_t port_,
                 struct wire_Controller *controller,
                 struct wire_list_public_key *current_keys,
                 struct wire_list_public_key *new_next_keys,
                 struct wire_StringList *witness_to_add,
                 struct wire_StringList *witness_to_remove,
                 uint64_t witness_threshold);

void wire_anchor(int64_t port_,
                 struct wire_Controller *controller,
                 struct wire_uint_8_list *data,
                 int32_t algo);

void wire_anchor_digest(int64_t port_,
                        struct wire_Controller *controller,
                        struct wire_StringList *sais);

void wire_add_watcher(int64_t port_,
                      struct wire_Controller *controller,
                      struct wire_uint_8_list *watcher_oobi);

void wire_finalize_event(int64_t port_,
                         struct wire_Controller *identifier,
                         struct wire_uint_8_list *event,
                         struct wire_Signature *signature);

void wire_resolve_oobi(int64_t port_, struct wire_uint_8_list *oobi_json);

void wire_query(int64_t port_,
                struct wire_Controller *controller,
                struct wire_uint_8_list *oobis_json);

void wire_process_stream(int64_t port_, struct wire_uint_8_list *stream);

void wire_get_kel(int64_t port_, struct wire_Controller *cont);

void wire_get_kel_by_str(int64_t port_, struct wire_uint_8_list *cont_id);

void wire_get_current_public_key(int64_t port_, struct wire_uint_8_list *attachment);

struct wire_StringList *new_StringList(int32_t len);

struct wire_Config *new_box_autoadd_config(void);

struct wire_Controller *new_box_autoadd_controller(void);

struct wire_Signature *new_box_autoadd_signature(void);

struct wire_list_public_key *new_list_public_key(int32_t len);

struct wire_uint_8_list *new_uint_8_list(int32_t len);

void free_WireSyncReturnStruct(struct WireSyncReturnStruct val);

void store_dart_post_cobject(DartPostCObjectFnType ptr);

static int64_t dummy_method_to_enforce_bundling(void) {
    int64_t dummy_var = 0;
    dummy_var ^= ((int64_t) (void*) wire_with_initial_oobis);
    dummy_var ^= ((int64_t) (void*) wire_init_kel);
    dummy_var ^= ((int64_t) (void*) wire_incept);
    dummy_var ^= ((int64_t) (void*) wire_finalize_inception);
    dummy_var ^= ((int64_t) (void*) wire_rotate);
    dummy_var ^= ((int64_t) (void*) wire_anchor);
    dummy_var ^= ((int64_t) (void*) wire_anchor_digest);
    dummy_var ^= ((int64_t) (void*) wire_add_watcher);
    dummy_var ^= ((int64_t) (void*) wire_finalize_event);
    dummy_var ^= ((int64_t) (void*) wire_resolve_oobi);
    dummy_var ^= ((int64_t) (void*) wire_query);
    dummy_var ^= ((int64_t) (void*) wire_process_stream);
    dummy_var ^= ((int64_t) (void*) wire_get_kel);
    dummy_var ^= ((int64_t) (void*) wire_get_kel_by_str);
    dummy_var ^= ((int64_t) (void*) wire_get_current_public_key);
    dummy_var ^= ((int64_t) (void*) new_StringList);
    dummy_var ^= ((int64_t) (void*) new_box_autoadd_config);
    dummy_var ^= ((int64_t) (void*) new_box_autoadd_controller);
    dummy_var ^= ((int64_t) (void*) new_box_autoadd_signature);
    dummy_var ^= ((int64_t) (void*) new_list_public_key);
    dummy_var ^= ((int64_t) (void*) new_uint_8_list);
    dummy_var ^= ((int64_t) (void*) free_WireSyncReturnStruct);
    dummy_var ^= ((int64_t) (void*) store_dart_post_cobject);
    return dummy_var;
}