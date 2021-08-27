'use strict';

const nacl = require("tweetnacl");
const util = require("tweetnacl-util");
const keri = require('./index')

const currentKeyPair = nacl.sign.keyPair();
const nextKeyPair = nacl.sign.keyPair();
const newNextKeyPair = nacl.sign.keyPair();

let default_key_type = 'Ed25519'

let inception_event = keri.incept( default_key_type, currentKeyPair.publicKey, default_key_type, nextKeyPair.publicKey)
let signature = nacl.sign.detached(inception_event, currentKeyPair.secretKey);

const signedd = util.encodeBase64(signature);

var controller = new keri.Controller(inception_event, signature)
console.log("Controller's key event log:\n " + controller.get_kel() + "\n")

let rotation_event = controller.rotate(default_key_type, nextKeyPair.publicKey, default_key_type, newNextKeyPair.publicKey)
signature = nacl.sign.detached(rotation_event, nextKeyPair.secretKey);
if (controller.finalize_rotation(rotation_event, signature)) {
	console.log("Keys rotated succesfully\n")
}
console.log("Controller's key event log after rotation:\n " + controller.get_kel() + "\n")

let message = util.decodeUTF8("message")
signature = nacl.sign.detached(message, nextKeyPair.secretKey);
let prefix = controller.get_prefix()

console.log(nacl.sign.detached.verify(message, signature, nextKeyPair.publicKey))

console.log(controller.verify(message, signature, prefix))
