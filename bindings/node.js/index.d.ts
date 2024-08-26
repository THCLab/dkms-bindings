/* tslint:disable */
/* eslint-disable */

/* auto-generated by NAPI-RS */

export interface Configs {
  dbPath?: string
  initialOobis?: string
}
export interface Key {
  p: string
}
export interface Signature {
  p: string
}
export const enum KeyType {
  ECDSAsecp256k1 = 0,
  Ed25519 = 1,
  Ed448 = 2,
  X25519 = 3,
  X448 = 4
}
export const enum SignatureType {
  Ed25519Sha512 = 0,
  ECDSAsecp256k1Sha256 = 1,
  Ed448 = 2
}
export class ConfigBuilder {
  dbPath?: string
  initialOobis?: string
  constructor(dbPath?: string, initialOobis?: string)
  withInitialOobis(oobisJson: string): ConfigBuilder
  withDbPath(dbPath: string): ConfigBuilder
  build(): Configs
}
export type JsPublicKey = PublicKey
export class PublicKey {
  prefix: string
  constructor(algorithm: KeyType, key: Buffer)
  getKey(): Key
}
export class SignatureBuilder {
  prefix: string
  constructor(algorithm: SignatureType, signature: Buffer)
  getSignature(): Signature
}
export class RegistryInceptionData {
  ixn: Buffer
  registryId: string
}
export class IssuanceData {
  ixn: Buffer
  vcHash: string
}
export class JsIdentifier {
  getKel(): Promise<string>
  findState(aboutId: string): Promise<string>
  getId(): Promise<string>
  notifyWitness(): Promise<void>
  queryMailbox(): Promise<Array<Buffer>>
  finalizeQueryMailbox(queries: Array<Buffer>, signatures: Array<Signature>): Promise<void>
  inceptRegistry(): Promise<RegistryInceptionData>
  finalizeInceptRegistry(event: Buffer, signature: Signature): Promise<void>
  issue(vc: Buffer): Promise<IssuanceData>
  finalizeIssue(event: Buffer, signature: Signature): Promise<void>
  notifyBackers(): Promise<void>
  addWatcher(watcherOobi: string): Promise<Buffer>
  finalizeAddWatcher(event: Buffer, signature: Signature): Promise<void>
  queryKel(aboutId: string, sn: number, digest: string): Promise<Array<Buffer>>
  finalizeQueryKel(qries: Array<Buffer>, signatures: Array<Signature>): Promise<boolean>
  queryFullKel(aboutId: string): Promise<Array<Buffer>>
  vcState(digest: string): Promise<string>
  sendOobiToWatcher(oobi: string): Promise<void>
  queryTel(registryId: string, vcId: string): Promise<Buffer>
  finalizeQueryTel(event: Buffer, signature: Signature): Promise<void>
  oobi(): Promise<Array<string>>
  registryIdOobi(): Promise<Array<string> | null>
}
export type JsController = Controller
export class Controller {
  constructor(config?: Configs | undefined | null)
  incept(pks: Array<Key>, npks: Array<Key>, witnesses: Array<string>, witnessThreshold: number): Promise<Buffer>
  finalizeInception(icpEvent: Buffer, signatures: Array<Signature>): JsIdentifier
}
