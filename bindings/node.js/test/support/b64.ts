import URLSafeBase64 from 'urlsafe-base64';

let b64EncodeUrlSafe = (p: Uint8Array) => URLSafeBase64.encode(Buffer.from(p));

export { b64EncodeUrlSafe };
