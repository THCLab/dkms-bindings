# Installation

`npm i keri.js`

# Overview

Javascript (NodeJS) client for managing KERI based Identifiers. See top level [README](https://github.com/THCLab/keri-bindings) to get acquainted with more generic overview and clients features.

## A note for consumers

This library requires a third party key provider that derives public private key pairs. It is on the consumer shoulders to manage key pairs in a secure way. Nowadays various approaches exist to tackle this problem, ie. TPM mentioned below or others like HSM or Secure Element.

This library also advocates cryptographic agility, hence it does not enforce to use any specific cryptographic primitives (one way hash functions and asymmetric key pairs used internally). Most modern are supported and it is up to consumer to pick whatever is appropriate. Nevertheless we propose to use `Blake3` hash function and `Ed25519` curve to derive key pairs.

## Glossary

* **Controller** -- manages Identifiers;
* **KERI** -- see https://keri.one/ page;

# Usage

See tests.

## Interface overview

Most methods listed below require a three step process to either establish new Identifier and its KEL or to append changes to the KEL. The process goes as following:
* prepare data for external signature;
* sign data;
* provide data along with signature to desired `finalizeX`.

It may look quite complex, as any time signature is required, an external third party must be interacted with to provide the signature. However, delegation the keys management to the consumers is not to move the burden on their shoulders, but to allow them to decide in what way they deem reasonable, secure and possible in their environment and use case.

### `#anchor`

Creates new Interaction Event along with arbitrary data. The purpose of Interaction Events is anchoring into the Identifier KEL anything that may be considered significant in given use case. Since KEL is a form of a provenance log, it is also an authentic evidence of events that have happened, hence anchoring arbitrary data allows to prove that such data have been seen or is related to given Identifier.

* `keri.anchor(ListOfDigests: Array): InteractionEvent`

### `#getKel`

Returns Key Event Log in the CESR representation for current Identifier.

* `controller.getKel(): String`

### `#finalizeAnchor`

Finalizes appending `InteractionEvent` to KEL.

* `controller.finalizeAnchor(icp: InteractionEvent, sig: Signature): Controller`

### `#finalizeIncept`

Finalizes inception (bootstrapping an Identifier and its Key Event Log).

* `controller.finalizeIncept(icp: InceptionEvent, sig: Signature): Controller`

### `.incept`

Creates inception event that needs to be signed externally.

* `controller.incept(currentNextKeyPairs: Array): InceptionEvent`

### `#rotate`

Creates rotation event that needs to be signed externally.

* `controller.rotate(currentNextKeyPairs: Array): RotationEvent`

