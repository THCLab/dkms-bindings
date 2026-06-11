# Facade parity — keri-kotlin ↔ keriox-sdk

`keriox-sdk` splits its surface in two:

| Layer | Path | For |
|-------|------|-----|
| High-level facade | crate root (`Keri`, `Identity`, `Group`, …) | most applications |
| Mid-level API | `keri_sdk::advanced::*` (`KeriStore`, `operations`, `signing`, `tel`, `keyprovider_adapter`, …) | flows the facade does not cover |

This binding builds on **both**:

- The high-level convenience operations delegate to a `keri_sdk::Keri` facade —
  see [Delegated](#facade-operations-delegated-to-the-sdk).
- The mobile/cyfron-specific surface (raw CESR signing, OOBI/watcher plumbing,
  out-of-band delegation, group rotation, …) stays on the **mid-level API**,
  because the facade does not expose it and the mobile key model keeps signing
  keys in the host keystore rather than in software seeds on disk — see
  [Not covered](#binding-operations-the-sdk-facade-does-not-cover).

---

## Sharing one store between the two layers

`KeriMobileSdk` owns a single cached `keri_sdk::advanced::KeriStore`. The facade
is built on demand with **`keri_sdk::Keri::from_store(store)`**, which wraps that
same `Arc<KeriStore>` and shares its controller cache. Both layers then run side
by side against one set of databases.

This is the fix for the redb lock collision: redb allows only one open
`Database` per file per process, and each `KeriStore` keeps its own controller
cache, so a second `Keri::open` over the binding's directory would deadlock on
redb's exclusive file lock the moment the same alias is touched. `from_store`
(added in keriox-sdk `ddf8dbd2`) avoids opening the databases a second time.

> Earlier revisions of this binding re-implemented the facade operations over
> `advanced::*` precisely because no `from_store` existed. That workaround is
> gone — the operations below now call the real facade.

---

## Facade operations delegated to the SDK

Implemented in `api.rs` by calling `self.facade()` (a `Keri` over the shared
store):

| Binding method | Facade call | Notes |
|----------------|-------------|-------|
| `list_identities()` | `Keri::identities()` | own identities only; excludes `.contacts/…` and bookkeeping aliases |
| `verify_any(cesr)` | `Keri::verify(cesr)` | verifies against every known identity + contact; purely local |
| `import_contact(source)` | `Keri::import_contact(source)` | accepts an OOBI URL or a raw KEL CESR string; stores under `.contacts/<id>` |
| `credential_status(id)` | `Keri::credential_status(id)` | self-contained `"<registry>:<said>"` id; local pass then network pass |

The existing per-alias `verify(alias, cesr)`, `incept_registry`,
`issue_credential`, `revoke_credential`, `check_credential`,
`get_credential_status` are unchanged.

### Known limitation — provider-backed credential status

`Keri::credential_status`'s **network** refresh signs registry queries with
software seeds (`store.load_signer`), which provider-backed (keystore)
identities do not have. So for a keystore identity the delegated
`credential_status` covers only registries already synced locally; for an
explicit, provider-signed network check, callers use the binding's existing
`check_credential(alias, registry, said)` (which signs through the host
keystore via `get_signer`).

**SDK change that would close this:** let the facade's network-signing
operations accept an externally supplied signer / key provider, analogous to
`IdentityBuilder::key_providers` / `Identity::rotate_with_provider`, which
already exist for create/rotate.

---

## Binding operations the SDK facade does NOT cover

These remain implemented over `advanced::*`. They are candidates to lift into
the SDK facade so other consumers can share them.

### Raw CESR signing
- `sign_to_cesr(alias, json)` — emits `<json_payload><CESR_sigs>` for
  mesagkesto challenge/response. `Identity::sign` instead wraps the payload in
  a `{"p": …}` envelope (a different wire shape).
  **Facade gap:** an unwrapped "sign these exact bytes, attach CESR sigs"
  primitive.

### OOBI / watcher plumbing
- `resolve_oobi` / `send_oobi_to_watcher` — record a peer's
  `LocationScheme`/`EndRole` locally and push it to the authorised watcher.
- `query_kel_for(via_alias, target_aid)` — fetch an arbitrary AID's KEL via the
  alias's watcher, with the "no false-positive sync" guarantee.
- `kel_head(via_alias, aid)` — `(sn, said)` of the locally-stored KEL head.
- `export_kel_cesr_for(via_alias, aid)` — export an arbitrary AID's stored KEL.
- `add_watcher` / `remove_watcher` / `list_watchers` / `has_watcher` /
  `list_watcher_locations` — watcher lifecycle.
- `list_witnesses(alias)` — persisted `{eid, scheme, url}` triples.

  **Facade gap:** the facade models contacts via `import_contact` (OOBI URL or
  KEL) and hides watchers entirely. The cyfron flow needs explicit, low-level
  control over watcher authorisation and arbitrary-AID KEL queries. A facade
  `Contact`/`Watcher` API could cover this.

### Out-of-band delegation (mobile QR pairing)
- `request_delegation` / `request_delegation_with_kel` / `import_delegator_kel`
  / `finalize_delegation` / `publish_delegation_to_witnesses`.

  The facade's delegation is **mailbox-based**: `build_delegation_request` →
  delegator sees it in `pending_requests()` → `approve()` →
  `DelegationHandle::finalize()`, coordinated through a shared witness. The
  mobile flow instead exchanges the `dip`/`ixn` CESR **out-of-band** (over a QR
  channel) and carries the delegator's KEL inline, with no shared witness
  mailbox between the two devices.

  **Facade gap:** an out-of-band delegation path (produce/consume the dip and
  delegating-ixn CESR explicitly, ingest a counterpart KEL directly) alongside
  the existing mailbox path.

### Group rotation
- `rotate_group(alias, group_aid, config)` — rotate a multisig group with an
  explicit post-rotation participant set and signing/next/witness thresholds
  (used to add/remove a device).

  `Group::rotate()` only handles a simple numeric threshold and reuses the full
  current member set; it rejects weighted thresholds and cannot drop a member.

  **Facade gap:** `Group::rotate_with(participants, thresholds, witness_changes)`.

### Store / identity deletion
- `wipe()` — drop the cached store and delete `db_path`.
- `delete_identifier(alias)` — forget a single alias (used to roll back a
  half-minted delegated AID).

  **Facade gap:** the facade has no delete/forget API.

### Provider-backed key management
- `create_identifier` / `rotate_keys` mint and rotate keys held in the host
  keystore, with per-alias key-label/version bookkeeping
  (`<alias>_v1`, `_v2`, …) in `key_state.json`, plus persisted witness/watcher
  `LocationScheme` lists (`witnesses.json` / `watchers.json`).

  The facade supports provider-backed identities
  (`IdentityBuilder::key_providers`, `Identity::rotate_with_provider`) but
  expects the *caller* to hold the `Arc<dyn KeyProvider>` instances and supply
  the new next provider on each rotation. The binding owns a
  `HostKeyProviderFactory` and manages the label/version lifecycle so the
  Android side only deals with aliases.

  **Facade gap:** a factory-driven provider model (create/open/rotate keys by
  label) so label bookkeeping does not have to live in every consumer.

---

## Other newly available SDK options (not yet used)

- `Keri::open_with_storage(path, StorageConfig::InMemory)` and
  `KeriStore::open_with_storage` give a fully ephemeral store whose event
  databases never touch disk — useful for tests/ephemeral agents. The binding
  always opens a file-backed store at `db_path`; an in-memory mode could be
  exposed for test harnesses if needed.
