'use strict';

const keri = require('./index.node');

class KeriController {
  constructor(prefix) {
    this.prefix = prefix;
    this.controller = new keri.Controller(prefix);

    return new Proxy(this, {
      get: (target, name) => {
        let t = target.controller;
        let n = name[0].toLowerCase() + name.slice(1, name.length).replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
        if( n in t || n == "then") {
          return t[n].bind(t);
        } else if(name in target) {
          return target[n];
        } else if(n == "toJSON") {
          return function() { return t; };
        }

        if(typeof(t) == "object") {
          if(t.constructor.name == "Object") {
            t = JSON.stringify(t);
          } else {
            t= t.constructor.name;
          }
        }
        throw new Error(`"${n}" is not part of ${t}`);
      }
    });
  }
}

module.exports = {
  ...keri,
  finalizeIncept: (icpEvent, signature) => {
    let prefix = keri.finalize_incept(icpEvent, signature);
    return new KeriController(prefix);
  },
  Controller: KeriController
};
