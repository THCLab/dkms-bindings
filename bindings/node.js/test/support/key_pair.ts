import nacl from "tweetnacl";

export default class KeyPair {
  public readonly pubKey: Uint8Array;
  private readonly privKey: Uint8Array;

  constructor() {
    let keyPair = nacl.sign.keyPair();
    this.pubKey = keyPair.publicKey;
    this.privKey = keyPair.secretKey;
  }

  sign(payload: Uint8Array) {
    return nacl.sign.detached(payload, this.privKey);
  }
}
