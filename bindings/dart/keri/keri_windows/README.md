# keri_windows

Windows implementation of the `keri` Flutter plugin.

**Status: not implemented yet.** Stub package present so the federated plugin
resolution doesn't complain on Windows hosts.

A future implementation would back the key provider with the Windows
Credential Manager / NCrypt (CNG) for hardware-backed P-256 where TPM is
available, falling back to software Ed25519 with DPAPI-protected seeds
otherwise.
