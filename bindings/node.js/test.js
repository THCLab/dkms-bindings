'use strict';

const nacl = require("tweetnacl");
const util = require("tweetnacl-util");
const keri = require('./index.js')
const {Base64} = require('js-base64');

const currentKeyPair = nacl.sign.keyPair();
const nextKeyPair = nacl.sign.keyPair();
const newNextKeyPair = nacl.sign.keyPair();

let keyB64 = Base64.encode(currentKeyPair.publicKey, true) // true to remove padding =
let nextKeyB64 = Base64.encode(nextKeyPair.publicKey, true)
let nextNextKeyB64 = Base64.encode(newNextKeyPair.publicKey, true)
let curPrefix = "D".concat(keyB64) // attach derivation code.
let nextPrefix = "D".concat(nextKeyB64)
let nextNextPrefix = "D".concat(nextNextKeyB64)

let inceptionEvent = keri.incept(curPrefix, nextPrefix)

let signature = nacl.sign.detached(inceptionEvent, currentKeyPair.secretKey);

let signatureB64 = Base64.encode(signature, true);
let signPrefix = "0B".concat(signatureB64) // attach derivation code.

let controller = keri.finalizeIncept(inceptionEvent, signPrefix)
let prefix = controller.prefix;

console.log("Controller's key event log:\n " + controller.getKel() + "\n")

let rotationEvent = controller.rotate(nextPrefix, nextNextPrefix)
signature = nacl.sign.detached(rotationEvent, nextKeyPair.secretKey);

signatureB64 = Base64.encode(signature, true);
signPrefix = "0B".concat(signatureB64) // attach derivation code.

if (controller.finalizeRotation(rotationEvent, signPrefix)) {
  console.log("Keys rotated succesfully\n")
}
console.log("Controller's key event log after rotation:\n " + controller.getKel() + "\n")

let message = util.decodeUTF8("message")
signature = nacl.sign.detached(message, nextKeyPair.secretKey);

signatureB64 = Base64.encode(signature, true);
signPrefix = "0B".concat(signatureB64)


// Verify in js
console.log(nacl.sign.detached.verify(message, signature, nextKeyPair.publicKey))

// Verify using controller
console.log(controller.verify(message, signPrefix, prefix))

try {
  new keri.Controller("DeXBCH8bD42XDW8T7-ryDXrS0MSMw13EBZkAsYFnLdno")
} catch (error) {
  console.error(error);
}
