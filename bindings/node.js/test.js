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

let signature = nacl.sign.detached(inceptionEvent, currentKeyPair.secretKey);

let signatureB64 = Base64.encode(signature, true);
let signPrefix = "0B".concat(signatureB64) // attach derivation code.

try {
  let controller = keri.finalizeIncept(inceptionEvent, [signPrefix])
} catch (e) {
  // Not enough signatures error
  console.log("Not enough signature. Controller can't be initialized")
}

signature = nacl.sign.detached(inceptionEvent, secondCurrentKeyPair.secretKey);

signatureB64 = Base64.encode(signature, true);
let secondSignPrefix = "0B".concat(signatureB64) // attach derivation code.

let controller = keri.finalizeIncept(inceptionEvent, [secondSignPrefix, signPrefix])
console.log(controller)
let prefix = controller.prefix;

console.log("Controller's key event log:\n " + controller.getKel() + "\n")

let rotationEvent = controller.rotate([[nextPrefix, nextNextPrefix], [snextPrefix, snextNextPrefix]])
console.log("rot: \n" + rotationEvent.toString("utf8") + "\n")
signature = nacl.sign.detached(rotationEvent, nextKeyPair.secretKey);
let signature2 = nacl.sign.detached(rotationEvent, secondNextKeyPair.secretKey);

signatureB64 = Base64.encode(signature, true);
signPrefix = "0B".concat(signatureB64) // attach derivation code.
let signatureB642 = Base64.encode(signature2, true);
let signPrefix2 = "0B".concat(signatureB642) // attach derivation code.

if (controller.finalizeRotation(rotationEvent, [signPrefix, signPrefix2])) {
  console.log("Keys rotated succesfully\n")
}
console.log("Controller's key event log after rotation:\n " + controller.getKel() + "\n")

let message = util.decodeUTF8("message")
signature = nacl.sign.detached(message, nextKeyPair.secretKey);

signatureB64 = Base64.encode(signature, true);
signPrefix = "0B".concat(signatureB64)


// // Verify in js
// console.log(nacl.sign.detached.verify(message, signature, nextKeyPair.publicKey))

// // Verify using controller
// console.log(controller.verify(message, signPrefix, prefix))

// try {
//   // Try to load non-existing identifier.
//   new keri.Controller("DeXBCH8bD42XDW8T7-ryDXrS0MSMw13EBZkAsYFnLdno")
// } catch (error) {
//   console.log(error.message);
// }
// try {
//   // Try to incept using with arbitrary text instead of identifier prefix as a public key. 
//   keri.incept("DeXBCH8bD42XDW8T7-ryDXrS0MSMw13EBZkAsYFnLdno", "no_next_key_prefix")
// } catch (e) {
//   console.log(e.message)
// }