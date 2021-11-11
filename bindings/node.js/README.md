# Overview

# Usage

## Bootstraping Controller

```
import keri from "index";
import Tpm from "test/support/tpm";
import keri from "index";

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

## Operational Modes

### Classic mode

### Multisig mode

## Interface overview
