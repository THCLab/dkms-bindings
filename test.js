'use strict';
(async function() {
	var assert = require('assert')
	const keri = require('.')
	let controller = new keri.Controller()

	let verifier = new keri.Controller()

	// Send controlle's key event log to verifier
	let kerl = controller.get_kerl()
	verifier.process_kerl(kerl)

	let message = "hi"
	let signature = controller.sign(message)
	let prefix = controller.get_prefix()

	let verify = verifier.verify(message, signature, prefix)
	assert(verify)

	// Save sn to choose proper public key for verification after rotation.
	let current_sn_while_signing = controller.get_current_sn();

	// Rotate controller's keys
	let rotation = controller.rotate()
	// Verifier needs to process controller's rotation event, to have his most
	// recent keys.
	verifier.process_kerl(rotation)
	
	// try to verify message again. It won't verify because current keys have
	// changed.
	verify = verifier.verify(message, signature, prefix)
	assert(!verify)

	// But if we specify sn of event which established keys used for signing
	// message, verification will work.
	verify = verifier.verify_at_sn(message, signature, prefix, current_sn_while_signing)
	assert(verify);

}());