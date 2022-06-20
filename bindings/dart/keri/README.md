
# Overview

Dart client for managing KERI based Identifiers. See top level [README](https://github.com/THCLab/keri-bindings) to get acquainted with more generic overview and clients features.  For more information about infrastructure see [KERI](https://keri.one/) or its [whitepaper](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf).

## Important
This plugin requires a third party key provider that derives public private key pairs and is able to sign a String using Ed25519 algorithm. For such a usecase, [Asymmetric crypto primitives](https://pub.dev/packages/asymmetric_crypto_primitives) plugin has been designed. The usage of its `signer` object along with KERI plugin has been provided as an example for this plugin.

## Usage
Currrently supported functions are:
* `initKel` - Initializes database for storing events.
* `incept` - Creates inception event that needs to be signed externally.
* `finalizeInception` - Finalizes inception (bootstrapping an Identifier and its Key Event Log).
* `rotate` - Creates rotation event that needs to be signed externally.
* `addWatcher` - Creates new reply message with identifier's watcher. It needs to be signed externally and finalized with finalizeEvent.
* `finalizeEvent` - Verifies provided signatures against event and saves it.
* `resolveOobi` - Checks and saves provided identifier's endpoint information.
* `query` - Query designated watcher about other identifier's public keys data.
* `getKel` - Returns Key Event Log in the CESR representation for current Identifier when given a controller.
* `getKelByStr` - Returns Key Event Log in the CESR representation for current Identifier when given a controller identifier.
* `getCurrentPublicKey` - Returns pairs: public key encoded in base64 and signature encoded in hex.

## Glossary

* **Controller** -- manages Identifiers;
* **KERI** -- see https://keri.one/ page;

## See also
* Test coverage provided in `functions_test.dart`: [link](https://github.com/THCLab/keri-bindings/blob/master/bindings/dart/keri/test/functions_test.dart) 