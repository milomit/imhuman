// End-to-end tests against a running dev server (`npm run dev`), using software passkeys.
// Run with: npm test   (set BASE to point somewhere other than http://localhost:8787)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SoftAuthenticator } from './soft-authenticator.js';
import { verifyReceipt } from '../public/passkey.js';

const BASE = process.env.BASE ?? 'http://localhost:8787';
const RP_ID = new URL(BASE).hostname;
const RUN = Math.random().toString(36).slice(2, 7);
const FAKE_IP = `10.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;

class Client {
  constructor(opts = {}) {
    this.cookie = '';
    this.phone = new SoftAuthenticator({ origin: BASE, rpId: RP_ID, ...opts });
  }

  async call(method, path, data, { origin = BASE } = {}) {
    const res = await fetch(BASE + path, {
      method,
      headers: {
        ...(method === 'GET' ? {} : { 'Content-Type': 'application/json', Origin: origin }),
        'CF-Connecting-IP': FAKE_IP,
        ...(this.cookie ? { Cookie: this.cookie } : {}),
      },
      body: method === 'GET' ? undefined : JSON.stringify(data ?? {}),
    });
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(';');
      this.cookie = pair.endsWith('=') ? '' : pair;
    }
    const json = await res.json().catch(() => null);
    if (Array.isArray(json)) return Object.assign(json, { http: res.status });
    return { http: res.status, ...json };
  }

  async ceremony(begin, finish, extra = {}, kind = 'get', getOpts) {
    const started = await this.call('POST', begin, extra);
    assert.ok(started.options, `${begin} failed: ${JSON.stringify(started)}`);
    const response = kind === 'create' ? await this.phone.create(started.options) : await this.phone.get(started.options, getOpts);
    return this.call('POST', finish, { ...extra, ceremonyId: started.ceremonyId, response });
  }

  signup(handle) {
    return this.ceremony('/api/signup/begin', '/api/signup/finish', { handle }, 'create');
  }

  login() {
    return this.ceremony('/api/login/begin', '/api/login/finish');
  }

  answer(id, code) {
    return this.ceremony(`/api/checks/${id}/begin`, `/api/checks/${id}/finish`, { code });
  }
}

const sam = new Client();
const jordan = new Client({ synced: true });
const mallory = new Client();
const handles = { sam: `sam_${RUN}`, jordan: `jordan_${RUN}`, mallory: `mal_${RUN}` };

test('sign up creates an account locked to a passkey', async () => {
  for (const [name, client] of [['sam', sam], ['jordan', jordan], ['mallory', mallory]]) {
    const res = await client.signup(handles[name]);
    assert.equal(res.http, 200, JSON.stringify(res));
    assert.equal(res.handle, handles[name]);
  }
  const me = await sam.call('GET', '/api/me');
  assert.equal(me.handle, handles.sam);
  assert.equal(me.freshness, 'today');
});

test('handles are unique and validated', async () => {
  const taken = await new Client().call('POST', '/api/signup/begin', { handle: handles.sam });
  assert.equal(taken.http, 409);
  const bad = await new Client().call('GET', '/api/handles/no');
  assert.equal(bad.available, false);
  const reserved = await new Client().call('GET', '/api/handles/admin');
  assert.equal(reserved.available, false);
});

test('a passkey without user verification (no face/fingerprint/passcode) is refused', async () => {
  const lazy = new Client({ uv: false });
  const res = await lazy.signup(`nouv_${RUN}`);
  assert.equal(res.http, 400);
  assert.equal(res.error, 'passkey_rejected');
});

test('requests from other websites are refused', async () => {
  const res = await sam.call('POST', '/api/checks', { to: handles.jordan }, { origin: 'https://evil.example' });
  assert.equal(res.http, 403);
  assert.equal(res.error, 'bad_origin');
});

test('signing out and back in with the passkey works', async () => {
  await sam.call('POST', '/api/logout');
  assert.equal((await sam.call('GET', '/api/me')).http, 401);
  const res = await sam.login();
  assert.equal(res.handle, handles.sam);
  assert.equal((await sam.call('GET', '/api/me')).handle, handles.sam);
});

let receipt;

test('the full prove-it check: send, answer with the words and a fresh face check, see the result', async () => {
  const check = await sam.call('POST', '/api/checks', { to: handles.jordan });
  assert.equal(check.http, 200, JSON.stringify(check));
  assert.equal(check.role, 'from');
  assert.equal(check.code.split('-').length, 3);
  assert.ok(check.link.endsWith(`#${check.code}`));

  const jordanView = await jordan.call('GET', `/api/checks/${check.id}`);
  assert.equal(jordanView.role, 'to');
  assert.equal(jordanView.code, undefined, 'the person answering must never be sent the words');

  const inbox = await jordan.call('GET', '/api/checks');
  assert.ok(inbox.incoming.some((k) => k.id === check.id));

  const wrong = await jordan.call('POST', `/api/checks/${check.id}/begin`, { code: 'apple-apple-apple' });
  assert.equal(wrong.error, 'wrong_code');

  const intruder = await mallory.call('POST', `/api/checks/${check.id}/begin`, { code: check.code });
  assert.equal(intruder.http, 403, 'someone else cannot answer a check addressed to jordan');

  const passed = await jordan.answer(check.id, check.code.replace(/-/g, ' ').toUpperCase());
  assert.equal(passed.http, 200, JSON.stringify(passed));
  assert.equal(passed.answeredBy, handles.jordan);

  const samView = await sam.call('GET', `/api/checks/${check.id}`);
  assert.equal(samView.status, 'passed');
  assert.equal(samView.answeredBy, handles.jordan);
  assert.equal(samView.keyType, 'synced');
  receipt = samView.receipt;

  const again = await jordan.call('POST', `/api/checks/${check.id}/begin`, { code: check.code });
  assert.equal(again.http, 409, 'a check can only be answered once');
});

test('receipts verify against the published key, and tampering is caught', async () => {
  const good = await verifyReceipt(receipt, `${BASE}/.well-known/jwks.json`);
  assert.equal(good.valid, true);
  assert.equal(good.claims.sub, handles.jordan);
  assert.equal(good.claims.aud, handles.sam);
  assert.equal(good.claims.result, 'passed');

  const [h, p, s] = receipt.split('.');
  const claims = JSON.parse(Buffer.from(p, 'base64url'));
  claims.sub = handles.mallory;
  const forged = `${h}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${s}`;
  assert.equal((await verifyReceipt(forged, `${BASE}/.well-known/jwks.json`)).valid, false);
});

test('a signature made for another website is refused (phishing protection)', async () => {
  const check = await sam.call('POST', '/api/checks', { to: handles.jordan });
  const started = await jordan.call('POST', `/api/checks/${check.id}/begin`, { code: check.code });
  const response = await jordan.phone.get(started.options, { origin: 'https://phishy.example' });
  const res = await jordan.call('POST', `/api/checks/${check.id}/finish`, { code: check.code, ceremonyId: started.ceremonyId, response });
  assert.equal(res.http, 400);
  assert.equal(res.error, 'passkey_rejected');
});

test('one passkey confirmation cannot be replayed', async () => {
  const check = await sam.call('POST', '/api/checks', { to: handles.jordan });
  const started = await jordan.call('POST', `/api/checks/${check.id}/begin`, { code: check.code });
  const response = await jordan.phone.get(started.options);
  const first = await jordan.call('POST', `/api/checks/${check.id}/finish`, { code: check.code, ceremonyId: started.ceremonyId, response });
  assert.equal(first.http, 200);
  const replay = await jordan.call('POST', `/api/checks/${check.id}/finish`, { code: check.code, ceremonyId: started.ceremonyId, response });
  assert.equal(replay.error, 'ceremony_expired');
});

test('five wrong guesses fail the check for good', async () => {
  const check = await sam.call('POST', '/api/checks', { to: handles.mallory });
  let last;
  for (let i = 0; i < 5; i++) last = await mallory.call('POST', `/api/checks/${check.id}/begin`, { code: 'zebra-zebra-zebra' });
  assert.equal(last.error, 'too_many_attempts');
  assert.equal((await sam.call('GET', `/api/checks/${check.id}`)).status, 'failed');
});

test('open links can be answered by whoever has them, and the sender learns their handle', async () => {
  const check = await sam.call('POST', '/api/checks', {});
  assert.equal(check.to, null);
  const res = await mallory.answer(check.id, check.code);
  assert.equal(res.http, 200, JSON.stringify(res));
  assert.equal((await sam.call('GET', `/api/checks/${check.id}`)).answeredBy, handles.mallory);
});

test('decline, block, and "only people I added" are respected', async () => {
  const check = await mallory.call('POST', '/api/checks', { to: handles.jordan });
  const declined = await jordan.call('POST', `/api/checks/${check.id}/decline`);
  assert.equal(declined.status, 'declined');

  await jordan.call('POST', '/api/blocks', { handle: handles.mallory });
  const blocked = await mallory.call('POST', '/api/checks', { to: handles.jordan });
  assert.equal(blocked.http, 403);
  await jordan.call('DELETE', `/api/blocks/${handles.mallory}`);

  await jordan.call('PATCH', '/api/me', { policy: 'contacts' });
  assert.equal((await mallory.call('POST', '/api/checks', { to: handles.jordan })).http, 403);
  await jordan.call('POST', '/api/contacts', { handle: handles.mallory });
  assert.equal((await mallory.call('POST', '/api/checks', { to: handles.jordan })).http, 200);
  await jordan.call('PATCH', '/api/me', { policy: 'anyone' });
});

test('one person cannot spam another with checks', async () => {
  let res;
  for (let i = 0; i < 4; i++) res = await sam.call('POST', '/api/checks', { to: handles.mallory });
  assert.equal(res.http, 429);
});

test('public profiles show freshness but never exact times', async () => {
  const p = await new Client().call('GET', `/api/users/${handles.jordan}`);
  assert.equal(p.freshness, 'today');
  assert.ok(p.checksPassed >= 2);
  assert.equal(p.lastCheckAt, undefined);
  const badge = await fetch(`${BASE}/api/badge/${handles.jordan}.svg`);
  assert.match(await badge.text(), /human · today/);
});

test('sensitive changes need a fresh face check, and deleting retires the handle', async () => {
  const doomed = new Client();
  const handle = `gone_${RUN}`;
  await doomed.signup(handle);
  const second = await doomed.ceremony('/api/passkeys/begin', '/api/passkeys/finish', {}, 'create');
  assert.equal(second.ok, true);
  assert.equal((await doomed.call('GET', '/api/passkeys')).length, 2);
  const del = await doomed.call('POST', '/api/me/delete');
  assert.equal(del.ok, true);
  const reuse = await new Client().call('GET', `/api/handles/${handle}`);
  assert.equal(reuse.available, false);
});
