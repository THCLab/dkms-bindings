
// See https://github.com/decentralized-identity/keri/blob/master/kids/kid0001.md#base64-master-code-table
// for count codes explanation.
let prefixedDerivative = (derivative: string) => `D${derivative}`;
let prefixedBlake3Digest = (derivative: string) => `E${derivative}`;
let prefixedSignature = (signature: string) => `0B${signature}`;

export {
  prefixedSignature,
  prefixedDerivative,
  prefixedBlake3Digest
};
