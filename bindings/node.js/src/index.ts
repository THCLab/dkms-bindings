'use strict';

const keri = require('../index.node');

type Controller = {
  [idx: string]: any;
};

// rotate
// anchor/interact
// addSignedEvent() <- new approach to finalizeRotate/finalizeAnchor...
// getKel()
// getEventsToBeSigned() // ie. multisig to be signed, delegation to be signed

/*
  let icpEvent = Controller.incept();
  let idController = Controller.createIdentifierController([icpEvent, signature]) // new approach to finalizeIncept
  
  let rotEvent = idController.rotate(...);
  idController.addSignedEvent([rotEvent, signature]);
  idController.getKel();
  
  let idController = Controller.getByIdentifier(idController.prefix);
  idController.getKel();
*/

export class IdentifierController {
  [idx: string]: any;
  private readonly identifierController: Controller;

  constructor(public readonly prefix: string) {
    this.identifierController = new keri.IdentifierController(prefix);

    return new Proxy(this, {
      get: (target, name: string) => {
        let t: Controller = target.identifierController;
        let n = name[0].toLowerCase() + name.slice(1, name.length).replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
        if( n in t || n == "then") {
          return t[n].bind(t);
        } else if(name in target) {
          return target[n];
        } else if(n == "toJSON") {
          return function() { return t; };
        }

        {
          let tt = "";
          if(typeof(t) == "object") {
            if(t.constructor.name == "Object") {
              tt = JSON.stringify(t);
            } else {
              tt = t.constructor.name;
            }
          }
          throw new Error(`"${n}" is not part of ${tt}`);
        }
      }
    });
  }
}

// incept();
// finalizeIncept => IdentifierController
// delegate
// createIdentifierController

export class Controller {
  [idx: string]: any;
  private readonly controller: Controller;

  constructor(public readonly prefix: string) {
    this.controller = new keri.Controller();

    return new Proxy(this, {
      get: (target, name: string) => {
        let t: Controller = target.controller;
        let n = name[0].toLowerCase() + name.slice(1, name.length).replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
        if( n in t || n == "then") {
          return t[n].bind(t);
        } else if(name in target) {
          return target[n];
        } else if(n == "toJSON") {
          return function() { return t; };
        }

        {
          let tt = "";
          if(typeof(t) == "object") {
            if(t.constructor.name == "Object") {
              tt = JSON.stringify(t);
            } else {
              tt = t.constructor.name;
            }
          }
          throw new Error(`"${n}" is not part of ${tt}`);
        }
      }
    });
  }
}

export default {
  incept: keri.incept,
  finalizeIncept: (icpEvent: Buffer, signatures: string[]) => {
    let prefix = keri.finalize_incept(icpEvent, signatures);
    return new IdentifierController(prefix);
  },
  Controller: KeriController,
  new: () => {
    return new KeriController("");
  },
};

