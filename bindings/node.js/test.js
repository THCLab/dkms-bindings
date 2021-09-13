'use strict';

const nacl = require("tweetnacl");
const util = require("tweetnacl-util");
const keri = require('./index.js')
const {Base64} = require('js-base64');

const currentKeyPair = nacl.sign.keyPair();
const secondCurrentKeyPair = nacl.sign.keyPair();
const nextKeyPair = nacl.sign.keyPair();
const secondNextKeyPair = nacl.sign.keyPair();
const newNextKeyPair = nacl.sign.keyPair();
const secondNewNextKeyPair = nacl.sign.keyPair();

let keyB64 = Base64.encode(currentKeyPair.publicKey, true) // true to remove padding =
let skeyB64 = Base64.encode(secondCurrentKeyPair.publicKey, true) // true to remove padding =
let nextKeyB64 = Base64.encode(nextKeyPair.publicKey, true)
let snextKeyB64 = Base64.encode(secondNextKeyPair.publicKey, true)
let nextNextKeyB64 = Base64.encode(newNextKeyPair.publicKey, true)
let snextNextKeyB64 = Base64.encode(secondNewNextKeyPair.publicKey, true)
let curPrefix = "D".concat(keyB64) // attach derivation code.
let scurPrefix = "D".concat(skeyB64) // attach derivation code.
let nextPrefix = "D".concat(nextKeyB64)
let snextPrefix = "D".concat(snextKeyB64)
let nextNextPrefix = "D".concat(nextNextKeyB64)
let snextNextPrefix = "D".concat(snextNextKeyB64)

let inceptionEvent = keri.incept([[curPrefix, nextPrefix, "1/2"], [scurPrefix, snextPrefix, "1/2"]])
console.log("icp: \n" + inceptionEvent.toString("utf8") + "\n")

let signature1 = nacl.sign.detached(inceptionEvent, currentKeyPair.secretKey);
let signatureB64 = Base64.encode(signature1, true);
let signPrefix = "0B".concat(signatureB64) // attach derivation code.

try {
  let controller = keri.finalizeIncept(inceptionEvent, [signPrefix])
} catch (e) {
  // Not enough signatures error
  console.log("Not enough signature. Controller can't be initialized.")
}

let signature2 = nacl.sign.detached(inceptionEvent, secondCurrentKeyPair.secretKey);
signatureB64 = Base64.encode(signature2, true);
let secondSignPrefix = "0B".concat(signatureB64) // attach derivation code.

console.log("Initializing controller with enough signatures: ")
let controller = keri.finalizeIncept(inceptionEvent, [secondSignPrefix, signPrefix])
console.log(controller)
let prefix = controller.prefix;

console.log("Controller's key event log:\n " + controller.getKel() + "\n")

// Make interaction event
let interactionEvent = controller.anchor("hi")
// Sign interaction event with enough signatures
signature1 = nacl.sign.detached(interactionEvent, currentKeyPair.secretKey);
signatureB64 = Base64.encode(signature1, true);
signPrefix = "0B".concat(signatureB64) // attach derivation code.

signature2 = nacl.sign.detached(interactionEvent, secondCurrentKeyPair.secretKey);
signatureB64 = Base64.encode(signature2, true);
secondSignPrefix = "0B".concat(signatureB64) // attach derivation code
// Process interaction event with signatures.
if (controller.finalizeAnchor(interactionEvent, [signPrefix, secondSignPrefix])) {
  console.log("Interaction event processed succesfully\n")
}

let rotationEvent = controller.rotate([[nextPrefix, nextNextPrefix, "1/2"], [snextPrefix, snextNextPrefix, "1/2"]])
console.log("rot: \n" + rotationEvent.toString("utf8") + "\n")
signature1 = nacl.sign.detached(rotationEvent, nextKeyPair.secretKey);
signature2 = nacl.sign.detached(rotationEvent, secondNextKeyPair.secretKey);

signatureB64 = Base64.encode(signature1, true);
signPrefix = "0B".concat(signatureB64) // attach derivation code.
let signatureB642 = Base64.encode(signature2, true);
let signPrefix2 = "0B".concat(signatureB642) // attach derivation code.

if (controller.finalizeRotation(rotationEvent, [signPrefix, signPrefix2])) {
  console.log("Keys rotated succesfully\n")
}
console.log("Controller's key event log after rotation:\n " + controller.getKel() + "\n")

let message = util.decodeUTF8("message")
signature1 = nacl.sign.detached(message, nextKeyPair.secretKey);

signatureB64 = Base64.encode(signature1, true);
let signPrefix1 = "0B".concat(signatureB64)

signature2 = nacl.sign.detached(message, secondNextKeyPair.secretKey);

signatureB64 = Base64.encode(signature2, true);
signPrefix2 = "0B".concat(signatureB64)

console.log("Verify using one signature (in js): ")
console.log(nacl.sign.detached.verify(message, signature1, nextKeyPair.publicKey))

// Verify using controller
try {
  console.log("Try to verify message using one signature... ")
  controller.verify(message, [signPrefix1], prefix)
} catch (e) {
  console.log("Not enough signatures error while verifing message.")
}

console.log("Try to verify message using two signatures... ")
console.log(controller.verify(message, [signPrefix1, signPrefix2], prefix))

try {
  console.log("Try to load non-existing identifier.")
  new keri.Controller("DeXBCH8bD42XDW8T7-ryDXrS0MSMw13EBZkAsYFnLdno")
} catch (error) {
  console.log(error.message);
}
try {
  console.log("Try to incept using with arbitrary text instead of identifier prefix as a public key..."); 
  keri.incept([["DeXBCH8bD42XDW8T7-ryDXrS0MSMw13EBZkAsYFnLdno", "no_next_key_prefix"]])
} catch (e) {
  console.log(e.message)
}