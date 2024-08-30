import nacl from "tweetnacl";
import * as fs from 'fs';

export default class KeyPair {
  public pubKey: Uint8Array;
  private privKey: Uint8Array;

  constructor() {
    let keyPair = nacl.sign.keyPair();
    this.pubKey = keyPair.publicKey;
    this.privKey = keyPair.secretKey;
  }

  save() {
    const pubKey = JSON.stringify(this.pubKey);
    const privKey = JSON.stringify(this.privKey);

    fs.writeFileSync('pub_key.json', pubKey, 'utf8');
    fs.writeFileSync('priv_key.json', privKey, 'utf8');
  }

  load() {
    const pubKey = JSON.parse(fs.readFileSync('pub_key.json', 'utf8'));
    const privKey = JSON.parse(fs.readFileSync('priv_key.json', 'utf8'));

    this.privKey = privKey;
    this.pubKey = pubKey;
    return this
  }
  
  sign(payload: Uint8Array) {
    return nacl.sign.detached(payload, this.privKey);
  }
}
