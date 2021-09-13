'use strict';

const keri = require('../index.node');

type Controller = {
  [idx: string]: any;

};

class KeriController {
  [idx: string]: any;
  private readonly controller: Controller;

  constructor(private readonly prefix: string) {
    this.controller = new keri.Controller(prefix);

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

module.exports = {
  ...keri,
  finalizeIncept: (icpEvent: string, signature: string) => {
    let prefix = keri.finalize_incept(icpEvent, signature);
    return new KeriController(prefix);
  },
  Controller: KeriController
};
