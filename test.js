'use strict';
(async function() {
	const keri = require('.')
	let controller = new keri.Controller()

	let verifier = new keri.Controller()

	let kerl = controller.get_kerl()

	// Send controllers kerl to verifier
	verifier.process_kerl(kerl)

	let signature = controller.sign("hi")
	let prefix = controller.get_prefix()

	let verify = verifier.verify("hi", signature, prefix)
	console.log("Verification before rotation:");
	console.log(verify);

	let rotation = controller.rotate()
	// Send rotation event to verifier.
	verifier.process_kerl(rotation)
	
	// try to verify message again.
	verify = verifier.verify("hi", signature, prefix)
	console.log("Verification after rotation:");
	console.log(verify);

}());