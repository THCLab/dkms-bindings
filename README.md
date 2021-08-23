# keri-neon

This project was bootstrapped by [create-neon](https://www.npmjs.com/package/create-neon).

## Installing keri-neon

Installing keri-neon requires a [supported version of Node and Rust](https://github.com/neon-bindings/neon#platform-support).

You can install the project with npm. In the project directory, run:

```sh
$ npm install
```

This fully installs the project, including installing any dependencies and running the build.

## Building keri-neon

If you have already installed the project and only want to run the build, run:

```sh
$ npm run build
```

This command uses the [cargo-cp-artifact](https://github.com/neon-bindings/cargo-cp-artifact) utility to run the Rust build and copy the built library into `./index.node`.

## Usage example

```
node test.js
```