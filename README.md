# License

EUPL 1.2 

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).

# Overview

A utility clients (see available [below](#available-clients)) that expose higher level interface for managing [KERI](https://keri.one/) based Identifiers.

With such a client one is able to:
* establising Identifiers;
* manage Identifiers (ie. rotation of current Identifier key to next key);
* use multi signature feature -- multi signature for Identifiers is a group based commitment of multiple actors, that according to established rules are required to provide their signature for any change within given Identifier;
* designate or remove a Witness for given Identifier **[WIP]**.

## Available clients

* [Node.JS](./bindings/node.js)
* [Dart](./bindings/dart)

# Development overview

Provides [KERIOX](https://github.com/THCLab/keriox) based bindings for various other languages either through FFI layer or other available approaches (ie. WASM).
