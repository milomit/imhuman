// Web Push with no third-party service: payload encryption per RFC 8291 (aes128gcm)
// and sender identification per RFC 8292 (VAPID), using only WebCrypto.
import { b64url, fromB64url, concat } from './util.js';

const enc = new TextEncoder();

async function hkdf(salt, ikm, info, length) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, length * 8);
  return new Uint8Array(bits);
}

export async function encryptPayload(plaintext, p256dhB64, authB64) {
  const uaPublic = fromB64url(p256dhB64);
  const authSecret = fromB64url(authB64);
  const asKeys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', asKeys.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdhSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, asKeys.privateKey, 256));

  const keyInfo = concat(enc.encode('WebPush: info\0'), uaPublic, asPublic);
  const ikm = await hkdf(authSecret, ecdhSecret, keyInfo, 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);

  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const padded = concat(plaintext, new Uint8Array([2]));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, padded));

  const header = new Uint8Array(21);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096);
  header[20] = asPublic.length;
  return concat(header, asPublic, ciphertext);
}

async function vapidAuthorization(env, endpoint) {
  const jwk = JSON.parse(env.VAPID_PRIVATE_KEY);
  const key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const header = b64url(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64url(enc.encode(JSON.stringify({
    aud: new URL(endpoint).origin,
    exp: Math.floor(Date.now() / 1000) + 12 * 60 * 60,
    sub: env.VAPID_SUBJECT,
  })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(`${header}.${claims}`));
  return `vapid t=${header}.${claims}.${b64url(sig)}, k=${env.VAPID_PUBLIC_KEY}`;
}

export function pushConfigured(env) {
  return Boolean(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY);
}

// Sends one notification to every device a person has turned alerts on for.
// Subscriptions the push service reports as gone are removed.
export async function notifyUser(env, userId, message) {
  if (!pushConfigured(env)) return;
  const { results } = await env.DB.prepare('SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = ?').bind(userId).all();
  const body = enc.encode(JSON.stringify(message));
  await Promise.all(results.map(async (sub) => {
    try {
      const res = await fetch(sub.endpoint, {
        method: 'POST',
        headers: {
          Authorization: await vapidAuthorization(env, sub.endpoint),
          'Content-Encoding': 'aes128gcm',
          'Content-Type': 'application/octet-stream',
          TTL: '300',
          Urgency: 'high',
        },
        body: await encryptPayload(body, sub.p256dh, sub.auth),
      });
      if (res.status === 404 || res.status === 410) {
        await env.DB.prepare('DELETE FROM push_subscriptions WHERE endpoint = ?').bind(sub.endpoint).run();
      }
    } catch (err) {
      console.warn('push failed', err?.message);
    }
  }));
}
