'use strict';

const nacl = require("tweetnacl");
const util = require("tweetnacl-util");
const keri = require('./index')
const {Base64} = require('js-base64');

const currentKeyPair = nacl.sign.keyPair();
const nextKeyPair = nacl.sign.keyPair();
const newNextKeyPair = nacl.sign.keyPair();

let key_b64 = Base64.encode(currentKeyPair.publicKey, true) // true to remove padding =
let next_key_b64 = Base64.encode(nextKeyPair.publicKey, true)
let new_next_key_b64 = Base64.encode(newNextKeyPair.publicKey, true)
let cur_prefix = "D".concat(key_b64) // attach derivation code.
let next_prefix = "D".concat(next_key_b64)
let new_next_prefix = "D".concat(new_next_key_b64)

let inception_event = keri.incept(cur_prefix, next_prefix)

let signature = nacl.sign.detached(inception_event, currentKeyPair.secretKey);

let signature_b64 = Base64.encode(signature, true);
let sign_prefix = "0B".concat(signature_b64) // attach derivation code.

var controller = new keri.Controller(inception_event, sign_prefix)
console.log("Controller's key event log:\n " + controller.get_kel() + "\n")

let rotation_event = controller.rotate(next_prefix, new_next_prefix)
signature = nacl.sign.detached(rotation_event, nextKeyPair.secretKey);

signature_b64 = Base64.encode(signature, true);
sign_prefix = "0B".concat(signature_b64) // attach derivation code.

if (controller.finalize_rotation(rotation_event, sign_prefix)) {
	console.log("Keys rotated succesfully\n")
}
console.log("Controller's key event log after rotation:\n " + controller.get_kel() + "\n")

let message = util.decodeUTF8("message")
signature = nacl.sign.detached(message, nextKeyPair.secretKey);

signature_b64 = Base64.encode(signature, true);
sign_prefix = "0B".concat(signature_b64)

let prefix = controller.get_prefix()

// Verify in js
console.log(nacl.sign.detached.verify(message, signature, nextKeyPair.publicKey))

// Verify using controller
console.log(controller.verify(message, sign_prefix, prefix))
