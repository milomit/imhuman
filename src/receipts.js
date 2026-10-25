// Signed receipts: every passed check produces a standard JWT (ES256) that anyone can verify
// against the public key published at /.well-known/jwks.json, without trusting this server's UI.
import { b64url } from './util.js';

const enc = new TextEncoder();
let cached;

async function loadKey(env) {
  if (cached?.raw === env.RECEIPT_KEY) return cached;
  if (!env.RECEIPT_KEY) throw new Error('RECEIPT_KEY is not set. Run `npm run setup`.');
  const jwk = JSON.parse(env.RECEIPT_KEY);
  const { d, key_ops, ext, ...pub } = jwk;
  const priv = await crypto.subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  cached = { raw: env.RECEIPT_KEY, priv, kid: jwk.kid, pub: { ...pub, use: 'sig', alg: 'ES256' } };
  return cached;
}

export async function signReceipt(env, claims) {
  const key = await loadKey(env);
  const header = { alg: 'ES256', typ: 'JWT', kid: key.kid };
  const input = `${b64url(enc.encode(JSON.stringify(header)))}.${b64url(enc.encode(JSON.stringify(claims)))}`;
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.priv, enc.encode(input));
  return `${input}.${b64url(sig)}`;
}

export async function jwks(env) {
  const key = await loadKey(env);
  return { keys: [key.pub] };
}
