# Overview

Javascript (NodeJS) client for managing KERI based Identifiers. See top level [README](https://github.com/THCLab/dkms-bindings) to get acquainted with more generic overview and clients features.

# Building

1. Install [napi](https://napi.rs/docs/introduction/getting-started#install-cli)
2. Run `npm run build`

# Usage

See [tests](https://github.com/THCLab/dkms-bindings/tree/master/bindings/node.js/test).


# A note for consumers

This library requires a third party key provider that derives public private key pairs. It is on the consumer shoulders to manage key pairs in a secure way. Nowadays various approaches exist to tackle this problem, ie. TPM mentioned below or others like HSM or Secure Element.

This library also advocates cryptographic agility, hence it does not enforce to use any specific cryptographic primitives (one way hash functions and asymmetric key pairs used internally). Most modern are supported and it is up to consumer to pick whatever is appropriate. Nevertheless we propose to use `Blake3` hash function and `Ed25519` curve to derive key pairs.

## Glossary

* **Controller** -- manages Identifiers;
* **KERI** -- see https://keri.one/ page;

## Interface overview

Most methods require a three step process to either establish new Identifier and its KEL or to append changes to the KEL. The process goes as following:
* prepare data for external signature;
* sign data;
* provide data along with signature to desired `finalizeX`.

It may look quite complex, as any time signature is required, an external third party must be interacted with to provide the signature. However, delegation the keys management to the consumers is not to move the burden on their shoulders, but to allow them to decide in what way they deem reasonable, secure and possible in their environment and use case. All those functions are available in the `mechanics` module.

The `issuing` and `signing` modules provide high-level functionality, leveraging functions from the `mechanics` module to set up identifiers. The `issuing` module handles identifiers that utilize both KEL and TEL, while the `signing` module is focused on identifiers using KEL only.