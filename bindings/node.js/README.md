# Overview

Javascript (NodeJS) client for managing KERI based Identifiers. See top level [README](https://github.com/THCLab/keri-bindings) to get acquainted with more generic overview and clients features.

## A note for consumers

This library requires a third party key provider that derives public private key pairs. It is on the consumer shoulders to manage key pairs in a secure way. Nowadays various approaches exist to tackle this problem, ie. TPM mentioned below or others like HSM or Secure Element.

This library also advocates cryptographic agility, hence it does not enforce to use any specific cryptographic primitives (one way hash functions and asymmetric key pairs used internally). Most modern are supported and it is up to consumer to pick whatever is appropriate. Nevertheless we propose to use `Blake3` hash function and `Ed25519` curve to derive key pairs.

## Glossary

* **Controller** -- manages Identifiers;
* **KERI** -- see https://keri.one/ page;
* **TPM** -- [Trusted Platform Module](https://en.wikipedia.org/wiki/Trusted_Platform_Module).


# Usage

## Bootstraping Controller

```
import keri from "index";
import Tpm from "./test/support/tpm";
import { b64EncodeUrlSafe } from "./test/support/b64";

const currentKeyManager = new Tpm();
// nextKeyManager is required for prerotation to be known
const nextKeyManager = new Tpm();

let inceptionEvent = keri.incept([[curKeySai, nextKeySai]]);

let signature = currentKeyManager.sign(inceptionEvent);

let controller = keri.finalizeIncept(
  inceptionEvent,
  [prefixedSignature(b64EncodeUrlSafe(signature))]
);
```

## Rotating current key

```
import keri from "index";
import Tpm from "./test/support/tpm";
import { b64EncodeUrlSafe } from "./test/support/b64";

const nextNextKeyManager = new Tpm();
let nextNextKeySai = prefixedDerivative(b64EncodeUrlSafe(nextNextKeyManager.pubKey));

let rotationEvent = controller.rotate([[nextKeySai, nextNextKeySai]])

signature = nextKeyManager.sign(rotationEvent);

let result = controller.finalizeRotation(
  rotationEvent,
  [prefixedSignature(b64EncodeUrlSafe(signature))]
);
```


## Operational Modes

### Classic mode

### Multisig mode

## Interface overview
