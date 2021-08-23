'use strict';
(async function() {
	const keri = require('.')
	let controller = new keri.Controller()

	let verifier = new keri.Controller()

	console.log(controller.get_kerl())
	controller.rotate()
	console.log("\n")
	console.log(controller.get_kerl())

	let kerl = controller.get_kerl()

	verifier.process_kerl(kerl)

	let signature = controller.sign("hi")
	let prefix = controller.get_prefix()
	let verify = verifier.verify("hi", signature, prefix)
	console.log(verify);

	let rotation = controller.rotate()
	verifier.process_kerl(rotation)
	let verif = verifier.verify("hi", signature, prefix)
	console.log(verif);

}());