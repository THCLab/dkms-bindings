
# Overview

Dart client for managing KERI based Identifiers. See top level [README](https://github.com/THCLab/keri-bindings) to get acquainted with more generic overview and clients features.  For more information about infrastructure see [KERI](https://keri.one/) or its [whitepaper](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf).

## Important
This plugin requires a third party key provider that derives public private key pairs and is able to sign a String using Ed25519 algorithm. For such a usecase, [Asymmetric crypto primitives](https://pub.dev/packages/asymmetric_crypto_primitives) plugin has been designed. The usage of its `signer` object along with KERI plugin has been provided as an example for this plugin. Moreover, it is important that the key is in **URL safe** variant of Base64.

## Usage
Currently supported functions are:
* `initKel` - Initializes database for storing events.
* `incept` - Creates inception event that needs to be signed externally.
* `finalizeInception` - Finalizes inception (bootstrapping an Identifier and its Key Event Log).
* `rotate` - Creates rotation event that needs to be signed externally.
* `addWatcher` - Creates new reply message with identifier's watcher. It needs to be signed externally and finalized with finalizeEvent.
* `finalizeEvent` - Verifies provided signatures against event and saves it.
* `resolveOobi` - Checks and saves provided identifier's endpoint information.
* `getKel` - Returns Key Event Log in the CESR representation for current Identifier when given a controller.
* `anchor` - Creates new Interaction Event along with arbitrary data.
* `anchorDigest` - Creates new Interaction Event along with provided Self Addressing Identifiers.
* `newIdentifier` - Creates an `Identifier` object from the id string.
* `queryMailbox` - Queries own or different mailbox about an identifier.
* `finalizeQuery` - Verifies provided signatures against mailbox query and saves it.
* `signatureFromHex` - Creates a `Signature` object from given type and hex string.
* `inceptGroup` - Creates group inception event that needs to be signed externally.
* `finalizeGroupIncept` - Finalizes group inception
* `newPublicKey` - Creates a `PublicKey` object from given key type and Base64 string.
* `newDataAndSignature` - Creates a `DataAndSignature` object from given data and its hex string signature.
* `queryWatchers` - Queries the watchers about an identifier.
* `sendOobiToWatcher` - Sends given oobi to a connected watcher 
* `notifyWitnesses` - Publishes events to the witnesses
* `broadcastReceipts` - Sends witnesses receipts between them
* `signToCesr` - Joins provided payload and signature into cesr stream.
* `verifyFromCesr` - Verifies signatures from provided cesr stream.
* `splitOobisAndData` - Splits provided stream into oobis and rest of cesr stream.
* `getMailboxLocation` - Returns the address where mailbox can be found.
* `anchorPayload` - Generates interaction event that anchors provided payload in the Key Event Log.

## Glossary

* **Controller** -- manages Identifiers;
* **KERI** -- see https://keri.one/ page;

## See also
* Test coverage provided in `functions_test.dart`: [link](https://github.com/THCLab/keri-bindings/blob/master/bindings/dart/keri/keri/test/functions_test.dart) 