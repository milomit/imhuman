import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { b64url, fromB64url, randomId, sha256b64, now, fail, DAY } from './util.js';

const SESSION_MS = 30 * DAY;
const CEREMONY_MS = 5 * 60 * 1000;
// Sensitive account changes need a face check within this window.
export const RECENT_MS = 5 * 60 * 1000;
// ES256, EdDSA, RS256: what phones and laptops actually use for passkeys.
const ALGORITHMS = [-7, -8, -257];

const secure = (env) => env.ORIGIN.startsWith('https://');
const cookieName = (env) => (secure(env) ? '__Host-hid' : 'hid');

export async function createSession(c, userId) {
  const token = randomId(32);
  const t = now();
  await c.env.DB.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at, verified_at) VALUES (?, ?, ?, ?, ?)')
    .bind(await sha256b64(token), userId, t, t + SESSION_MS, t)
    .run();
  setCookie(c, cookieName(c.env), token, {
    path: '/',
    httpOnly: true,
    secure: secure(c.env),
    sameSite: 'Lax',
    maxAge: SESSION_MS / 1000,
  });
}

export async function endSession(c) {
  const token = getCookie(c, cookieName(c.env));
  if (token) await c.env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256b64(token)).run();
  deleteCookie(c, cookieName(c.env), { path: '/', secure: secure(c.env) });
}

export async function currentSession(c) {
  const token = getCookie(c, cookieName(c.env));
  if (!token) return null;
  const tokenHash = await sha256b64(token);
  const row = await c.env.DB.prepare(
    `SELECT s.verified_at, u.id, u.handle, u.created_at, u.last_check_at, u.checks_passed, u.challenge_policy
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`,
  ).bind(tokenHash, now()).first();
  if (!row) return null;
  const { verified_at, ...user } = row;
  return { tokenHash, verifiedAt: verified_at, user };
}

// Each passkey ceremony gets a server-side row that is consumed exactly once.
export async function startCeremony(env, { purpose, challenge, userId = null, handle = null, webauthnUserId = null, ref = null }) {
  const id = randomId(16);
  await env.DB.prepare('INSERT INTO ceremonies (id, purpose, challenge, user_id, handle, webauthn_user_id, ref, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(id, purpose, challenge, userId, handle, webauthnUserId, ref, now() + CEREMONY_MS)
    .run();
  return id;
}

export async function takeCeremony(env, id, purpose) {
  const row = await env.DB.prepare('DELETE FROM ceremonies WHERE id = ? AND purpose = ? RETURNING *')
    .bind(String(id ?? ''), purpose)
    .first();
  if (!row || row.expires_at < now()) fail(400, 'ceremony_expired', 'That request expired. Try again.');
  return row;
}

export function registrationOptions(env, { handle, webauthnUserId, exclude = [] }) {
  return generateRegistrationOptions({
    rpName: env.RP_NAME,
    rpID: env.RP_ID,
    userName: `@${handle}`,
    userDisplayName: `@${handle}`,
    userID: fromB64url(webauthnUserId),
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    supportedAlgorithmIDs: ALGORITHMS,
    excludeCredentials: exclude,
    timeout: 120000,
  });
}

export async function verifyRegistration(env, ceremony, response) {
  let result;
  try {
    result = await verifyRegistrationResponse({
      response,
      expectedChallenge: ceremony.challenge,
      expectedOrigin: env.ORIGIN,
      expectedRPID: env.RP_ID,
      requireUserVerification: true,
      supportedAlgorithmIDs: ALGORITHMS,
    });
  } catch (err) {
    console.warn('registration rejected', err?.message);
    fail(400, 'passkey_rejected', "That passkey couldn't be verified. Try again.");
  }
  if (!result.verified || !result.registrationInfo.userVerified) {
    fail(400, 'passkey_rejected', 'Your phone has to confirm it is you with Face ID, fingerprint, or passcode.');
  }
  const info = result.registrationInfo;
  return {
    id: info.credential.id,
    publicKey: b64url(info.credential.publicKey),
    counter: info.credential.counter,
    transports: JSON.stringify(response?.response?.transports ?? []),
    deviceType: info.credentialDeviceType,
    backedUp: info.credentialBackedUp ? 1 : 0,
  };
}

export async function insertCredential(env, userId, cred) {
  await env.DB.prepare(
    'INSERT INTO credentials (id, user_id, public_key, counter, transports, device_type, backed_up, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  ).bind(cred.id, userId, cred.publicKey, cred.counter, cred.transports, cred.deviceType, cred.backedUp, now()).run();
}

export async function authenticationOptions(env, userId = null) {
  let allowCredentials;
  if (userId) {
    const { results } = await env.DB.prepare('SELECT id, transports FROM credentials WHERE user_id = ?').bind(userId).all();
    allowCredentials = results.map((r) => ({ id: r.id, transports: JSON.parse(r.transports || '[]') }));
  }
  return generateAuthenticationOptions({ rpID: env.RP_ID, userVerification: 'required', allowCredentials, timeout: 120000 });
}

// Verifies a fresh passkey signature with user verification (face, fingerprint, or device passcode).
export async function verifyAssertion(env, ceremony, response, { userId = null } = {}) {
  const cred = await env.DB.prepare('SELECT * FROM credentials WHERE id = ?').bind(String(response?.id ?? '')).first();
  if (!cred) fail(400, 'unknown_passkey', "That passkey isn't linked to any handle here.");
  if (userId && cred.user_id !== userId) fail(403, 'wrong_account', 'That passkey belongs to a different handle.');
  let result;
  try {
    result = await verifyAuthenticationResponse({
      response,
      expectedChallenge: ceremony.challenge,
      expectedOrigin: env.ORIGIN,
      expectedRPID: env.RP_ID,
      requireUserVerification: true,
      credential: {
        id: cred.id,
        publicKey: fromB64url(cred.public_key),
        counter: cred.counter,
        transports: JSON.parse(cred.transports || '[]'),
      },
    });
  } catch (err) {
    console.warn('assertion rejected', err?.message);
    fail(400, 'passkey_rejected', "Your phone didn't confirm it was you. Try again.");
  }
  const info = result.authenticationInfo;
  if (!result.verified || !info.userVerified) fail(400, 'passkey_rejected', "Your phone didn't confirm it was you. Try again.");
  await env.DB.prepare('UPDATE credentials SET counter = ?, last_used_at = ?, device_type = ?, backed_up = ? WHERE id = ?')
    .bind(info.newCounter, now(), info.credentialDeviceType, info.credentialBackedUp ? 1 : 0, cred.id)
    .run();
  return { userId: cred.user_id, deviceType: info.credentialDeviceType };
}

export async function rateLimit(env, key, limit, windowMs) {
  const t = now();
  const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM rate_events WHERE key = ? AND at > ?').bind(key, t - windowMs).first();
  if (row.n >= limit) fail(429, 'rate_limited', 'Too many tries. Wait a bit and try again.');
  await env.DB.prepare('INSERT INTO rate_events (key, at) VALUES (?, ?)').bind(key, t).run();
}
