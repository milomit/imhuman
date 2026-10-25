import { Hono } from 'hono';
import { renderSVG } from 'uqr';
import {
  createSession, endSession, currentSession, startCeremony, takeCeremony, registrationOptions,
  verifyRegistration, insertCredential, authenticationOptions, verifyAssertion, rateLimit, RECENT_MS,
} from './auth.js';
import { HttpError, fail, now, randomId, freshness, normalizeHandle, handleProblem, safeEqual, DAY } from './util.js';
import { newCode, normalizeCode } from './words.js';
import { signReceipt, jwks } from './receipts.js';
import { notifyUser, pushConfigured } from './push.js';

const CHECK_TTL_MS = 10 * 60 * 1000;
const MAX_CODE_ATTEMPTS = 5;
const HOUR = 60 * 60 * 1000;

const app = new Hono();

app.onError((err, c) => {
  if (err instanceof HttpError) return c.json({ error: err.code, message: err.message }, err.status);
  console.error(err);
  return c.json({ error: 'server_error', message: 'Something went wrong on our side. Try again.' }, 500);
});

app.use('/api/*', async (c, next) => {
  // Every state-changing request must come from our own pages (blocks cross-site request forgery).
  if (c.req.method !== 'GET' && c.req.header('Origin') !== c.env.ORIGIN) {
    fail(403, 'bad_origin', "Requests must come from the I'm Human site.");
  }
  await next();
  c.header('Cache-Control', 'no-store');
});

const ip = (c) => c.req.header('CF-Connecting-IP') ?? 'local';
const body = async (c) => {
  try {
    return await c.req.json();
  } catch {
    return {};
  }
};

async function requireSession(c) {
  const session = await currentSession(c);
  if (!session) fail(401, 'signed_out', 'Sign in first.');
  return session;
}

function requireRecent(session) {
  if (now() - session.verifiedAt > RECENT_MS) fail(403, 'reverify', 'Confirm with your face first.');
}

async function userByHandle(env, raw) {
  const handle = normalizeHandle(raw);
  const user = await env.DB.prepare('SELECT * FROM users WHERE handle = ?').bind(handle).first();
  if (!user) fail(404, 'no_such_handle', `Nobody on I'm Human is called @${handle}.`);
  return user;
}

async function keyType(env, userId) {
  const { results } = await env.DB.prepare('SELECT DISTINCT device_type FROM credentials WHERE user_id = ?').bind(userId).all();
  const types = results.map((r) => r.device_type);
  if (types.length === 1) return types[0] === 'singleDevice' ? 'device' : 'synced';
  return types.length ? 'mixed' : 'none';
}

function meView(user, session) {
  return {
    handle: user.handle,
    createdAt: user.created_at,
    lastCheckAt: user.last_check_at,
    freshness: freshness(user.last_check_at),
    checksPassed: user.checks_passed,
    policy: user.challenge_policy,
    verifiedAt: session?.verifiedAt ?? null,
  };
}

// A passkey ceremony with user verification proves someone is at the phone right now.
async function markPresent(env, userId, tokenHash) {
  const t = now();
  await env.DB.prepare('UPDATE users SET last_check_at = ? WHERE id = ?').bind(t, userId).run();
  if (tokenHash) await env.DB.prepare('UPDATE sessions SET verified_at = ? WHERE token_hash = ?').bind(t, tokenHash).run();
}

// ---------- Public config ----------

app.get('/api/config', (c) => c.json({
  rpName: c.env.RP_NAME,
  origin: c.env.ORIGIN,
  pushKey: pushConfigured(c.env) ? c.env.VAPID_PUBLIC_KEY : null,
}));

app.get('/.well-known/jwks.json', async (c) => {
  c.header('Access-Control-Allow-Origin', '*');
  c.header('Cache-Control', 'public, max-age=300');
  return c.json(await jwks(c.env));
});

// ---------- Sign up, sign in ----------

app.get('/api/handles/:handle', async (c) => {
  const handle = normalizeHandle(c.req.param('handle'));
  const problem = handleProblem(handle);
  if (problem) return c.json({ handle, available: false, problem });
  const taken = await c.env.DB.prepare('SELECT 1 FROM users WHERE handle = ? UNION SELECT 1 FROM retired_handles WHERE handle = ?').bind(handle, handle).first();
  return c.json({ handle, available: !taken, problem: taken ? 'That handle is taken.' : null });
});

app.post('/api/signup/begin', async (c) => {
  await rateLimit(c.env, `signup:${ip(c)}`, 20, HOUR);
  const handle = normalizeHandle((await body(c)).handle);
  const problem = handleProblem(handle);
  if (problem) fail(400, 'bad_handle', problem);
  const taken = await c.env.DB.prepare('SELECT 1 FROM users WHERE handle = ? UNION SELECT 1 FROM retired_handles WHERE handle = ?').bind(handle, handle).first();
  if (taken) fail(409, 'handle_taken', 'That handle is taken.');
  const webauthnUserId = randomId(16);
  const options = await registrationOptions(c.env, { handle, webauthnUserId });
  const ceremonyId = await startCeremony(c.env, { purpose: 'signup', challenge: options.challenge, handle, webauthnUserId });
  return c.json({ ceremonyId, options });
});

app.post('/api/signup/finish', async (c) => {
  const { ceremonyId, response } = await body(c);
  const ceremony = await takeCeremony(c.env, ceremonyId, 'signup');
  const cred = await verifyRegistration(c.env, ceremony, response);
  const t = now();
  try {
    await c.env.DB.batch([
      c.env.DB.prepare('INSERT INTO users (id, handle, created_at, last_check_at) VALUES (?, ?, ?, ?)').bind(ceremony.webauthn_user_id, ceremony.handle, t, t),
      c.env.DB.prepare(
        'INSERT INTO credentials (id, user_id, public_key, counter, transports, device_type, backed_up, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      ).bind(cred.id, ceremony.webauthn_user_id, cred.publicKey, cred.counter, cred.transports, cred.deviceType, cred.backedUp, t),
    ]);
  } catch (err) {
    if (String(err?.message).includes('UNIQUE')) fail(409, 'handle_taken', 'Someone just took that handle. Pick another.');
    throw err;
  }
  await createSession(c, ceremony.webauthn_user_id);
  return c.json({ handle: ceremony.handle });
});

app.post('/api/login/begin', async (c) => {
  await rateLimit(c.env, `login:${ip(c)}`, 30, 10 * 60 * 1000);
  const options = await authenticationOptions(c.env);
  const ceremonyId = await startCeremony(c.env, { purpose: 'login', challenge: options.challenge });
  return c.json({ ceremonyId, options });
});

app.post('/api/login/finish', async (c) => {
  const { ceremonyId, response } = await body(c);
  const ceremony = await takeCeremony(c.env, ceremonyId, 'login');
  const { userId } = await verifyAssertion(c.env, ceremony, response);
  await markPresent(c.env, userId);
  await createSession(c, userId);
  const user = await c.env.DB.prepare('SELECT handle FROM users WHERE id = ?').bind(userId).first();
  return c.json({ handle: user.handle });
});

app.post('/api/logout', async (c) => {
  await endSession(c);
  return c.json({ ok: true });
});

// ---------- Your account ----------

app.get('/api/me', async (c) => {
  const session = await requireSession(c);
  return c.json(meView(session.user, session));
});

app.patch('/api/me', async (c) => {
  const session = await requireSession(c);
  const { policy } = await body(c);
  if (!['anyone', 'contacts', 'nobody'].includes(policy)) fail(400, 'bad_policy', 'Pick anyone, contacts, or nobody.');
  await c.env.DB.prepare('UPDATE users SET challenge_policy = ? WHERE id = ?').bind(policy, session.user.id).run();
  return c.json(meView({ ...session.user, challenge_policy: policy }, session));
});

// The daily check: a glance at your phone keeps your badge fresh.
app.post('/api/presence/begin', async (c) => {
  const session = await requireSession(c);
  const options = await authenticationOptions(c.env, session.user.id);
  const ceremonyId = await startCeremony(c.env, { purpose: 'presence', challenge: options.challenge, userId: session.user.id });
  return c.json({ ceremonyId, options });
});

app.post('/api/presence/finish', async (c) => {
  const session = await requireSession(c);
  const { ceremonyId, response } = await body(c);
  const ceremony = await takeCeremony(c.env, ceremonyId, 'presence');
  if (ceremony.user_id !== session.user.id) fail(403, 'wrong_account', 'That request belongs to a different handle.');
  await verifyAssertion(c.env, ceremony, response, { userId: session.user.id });
  await markPresent(c.env, session.user.id, session.tokenHash);
  const t = now();
  return c.json(meView({ ...session.user, last_check_at: t }, { verifiedAt: t }));
});

app.get('/api/passkeys', async (c) => {
  const session = await requireSession(c);
  const { results } = await c.env.DB.prepare('SELECT id, device_type, backed_up, created_at, last_used_at FROM credentials WHERE user_id = ? ORDER BY created_at')
    .bind(session.user.id).all();
  return c.json(results.map((r) => ({ id: r.id, deviceType: r.device_type, backedUp: Boolean(r.backed_up), createdAt: r.created_at, lastUsedAt: r.last_used_at })));
});

app.post('/api/passkeys/begin', async (c) => {
  const session = await requireSession(c);
  requireRecent(session);
  const { results } = await c.env.DB.prepare('SELECT id, transports FROM credentials WHERE user_id = ?').bind(session.user.id).all();
  const options = await registrationOptions(c.env, {
    handle: session.user.handle,
    webauthnUserId: session.user.id,
    exclude: results.map((r) => ({ id: r.id, transports: JSON.parse(r.transports || '[]') })),
  });
  const ceremonyId = await startCeremony(c.env, { purpose: 'add-passkey', challenge: options.challenge, userId: session.user.id });
  return c.json({ ceremonyId, options });
});

app.post('/api/passkeys/finish', async (c) => {
  const session = await requireSession(c);
  const { ceremonyId, response } = await body(c);
  const ceremony = await takeCeremony(c.env, ceremonyId, 'add-passkey');
  if (ceremony.user_id !== session.user.id) fail(403, 'wrong_account', 'That request belongs to a different handle.');
  const cred = await verifyRegistration(c.env, ceremony, response);
  await insertCredential(c.env, session.user.id, cred);
  return c.json({ ok: true });
});

app.delete('/api/passkeys/:id', async (c) => {
  const session = await requireSession(c);
  requireRecent(session);
  const { n } = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM credentials WHERE user_id = ?').bind(session.user.id).first();
  if (n <= 1) fail(400, 'last_passkey', "You can't remove your only passkey. Add another one first.");
  await c.env.DB.prepare('DELETE FROM credentials WHERE id = ? AND user_id = ?').bind(c.req.param('id'), session.user.id).run();
  return c.json({ ok: true });
});

app.post('/api/me/delete', async (c) => {
  const session = await requireSession(c);
  requireRecent(session);
  await c.env.DB.batch([
    c.env.DB.prepare('INSERT OR IGNORE INTO retired_handles (handle, retired_at) VALUES (?, ?)').bind(session.user.handle, now()),
    c.env.DB.prepare('DELETE FROM users WHERE id = ?').bind(session.user.id),
  ]);
  await endSession(c);
  return c.json({ ok: true });
});

// ---------- Profiles, contacts, blocks ----------

async function canChallenge(env, from, to) {
  if (from.id === to.id) return { ok: false, reason: "You can't check yourself." };
  const blocked = await env.DB.prepare('SELECT 1 FROM blocks WHERE user_id = ? AND blocked_id = ?').bind(to.id, from.id).first();
  if (blocked || to.challenge_policy === 'nobody') return { ok: false, reason: `@${to.handle} isn't accepting checks right now.` };
  if (to.challenge_policy === 'contacts') {
    const added = await env.DB.prepare('SELECT 1 FROM contacts WHERE user_id = ? AND contact_id = ?').bind(to.id, from.id).first();
    if (!added) return { ok: false, reason: `@${to.handle} only accepts checks from people they've added.` };
  }
  return { ok: true };
}

app.get('/api/users/:handle', async (c) => {
  const user = await userByHandle(c.env, c.req.param('handle'));
  const session = await currentSession(c);
  const viewer = session?.user;
  const profile = {
    handle: user.handle,
    since: new Date(user.created_at).toISOString().slice(0, 7),
    freshness: freshness(user.last_check_at),
    checksPassed: user.checks_passed,
    keyType: await keyType(c.env, user.id),
  };
  if (viewer) {
    const contact = await c.env.DB.prepare('SELECT 1 FROM contacts WHERE user_id = ? AND contact_id = ?').bind(viewer.id, user.id).first();
    const blocked = await c.env.DB.prepare('SELECT 1 FROM blocks WHERE user_id = ? AND blocked_id = ?').bind(viewer.id, user.id).first();
    const check = await canChallenge(c.env, viewer, user);
    Object.assign(profile, { isMe: viewer.id === user.id, isContact: Boolean(contact), isBlocked: Boolean(blocked), canCheck: check.ok, cantCheckReason: check.ok ? null : check.reason });
  } else {
    c.header('Access-Control-Allow-Origin', '*');
  }
  return c.json(profile);
});

// A tiny live badge other sites can embed: <img src="https://your.domain/api/badge/handle.svg">
app.get('/api/badge/:file', async (c) => {
  const handle = normalizeHandle(c.req.param('file').replace(/\.svg$/, ''));
  const user = await c.env.DB.prepare('SELECT handle, last_check_at FROM users WHERE handle = ?').bind(handle).first();
  const state = user ? freshness(user.last_check_at) : 'unknown';
  const label = { today: 'human · today', week: 'human · this week', overdue: 'human · overdue', never: 'human · never checked', unknown: 'not found' }[state];
  const color = { today: '#1a7f4b', week: '#5f5e5a', overdue: '#a35a00', never: '#5f5e5a', unknown: '#a32d2d' }[state];
  const text = `@${handle}`;
  const w1 = 12 + text.length * 7;
  const w2 = 12 + label.length * 6.6;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w1 + w2}" height="22" role="img" aria-label="${text} ${label}"><rect width="${w1}" height="22" rx="4" fill="#2c2c2a"/><rect x="${w1 - 4}" width="${w2 + 4}" height="22" rx="4" fill="${color}"/><rect x="${w1 - 4}" width="4" height="22" fill="${color}"/><g fill="#fff" font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="12"><text x="6" y="15">${text}</text><text x="${w1 + 6}" y="15">${label}</text></g></svg>`;
  return c.body(svg, 200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=300', 'Access-Control-Allow-Origin': '*' });
});

app.get('/api/contacts', async (c) => {
  const session = await requireSession(c);
  const { results } = await c.env.DB.prepare(
    'SELECT u.handle, u.last_check_at FROM contacts k JOIN users u ON u.id = k.contact_id WHERE k.user_id = ? ORDER BY u.handle',
  ).bind(session.user.id).all();
  return c.json(results.map((r) => ({ handle: r.handle, freshness: freshness(r.last_check_at) })));
});

app.post('/api/contacts', async (c) => {
  const session = await requireSession(c);
  const user = await userByHandle(c.env, (await body(c)).handle);
  if (user.id === session.user.id) fail(400, 'self', "That's you.");
  await c.env.DB.prepare('INSERT OR IGNORE INTO contacts (user_id, contact_id, created_at) VALUES (?, ?, ?)').bind(session.user.id, user.id, now()).run();
  return c.json({ handle: user.handle, freshness: freshness(user.last_check_at) });
});

app.delete('/api/contacts/:handle', async (c) => {
  const session = await requireSession(c);
  const user = await userByHandle(c.env, c.req.param('handle'));
  await c.env.DB.prepare('DELETE FROM contacts WHERE user_id = ? AND contact_id = ?').bind(session.user.id, user.id).run();
  return c.json({ ok: true });
});

app.get('/api/blocks', async (c) => {
  const session = await requireSession(c);
  const { results } = await c.env.DB.prepare('SELECT u.handle FROM blocks b JOIN users u ON u.id = b.blocked_id WHERE b.user_id = ? ORDER BY u.handle')
    .bind(session.user.id).all();
  return c.json(results.map((r) => r.handle));
});

app.post('/api/blocks', async (c) => {
  const session = await requireSession(c);
  const user = await userByHandle(c.env, (await body(c)).handle);
  if (user.id === session.user.id) fail(400, 'self', "That's you.");
  await c.env.DB.batch([
    c.env.DB.prepare('INSERT OR IGNORE INTO blocks (user_id, blocked_id, created_at) VALUES (?, ?, ?)').bind(session.user.id, user.id, now()),
    c.env.DB.prepare('DELETE FROM contacts WHERE user_id = ? AND contact_id = ?').bind(session.user.id, user.id),
    c.env.DB.prepare("UPDATE checks SET status = 'declined' WHERE from_user_id = ? AND to_user_id = ? AND status = 'pending'").bind(user.id, session.user.id),
  ]);
  return c.json({ ok: true });
});

app.delete('/api/blocks/:handle', async (c) => {
  const session = await requireSession(c);
  const user = await userByHandle(c.env, c.req.param('handle'));
  await c.env.DB.prepare('DELETE FROM blocks WHERE user_id = ? AND blocked_id = ?').bind(session.user.id, user.id).run();
  return c.json({ ok: true });
});

// ---------- Human checks ----------

async function loadCheck(env, id) {
  const check = await env.DB.prepare(
    `SELECT k.*, f.handle AS from_handle, t.handle AS to_handle, a.handle AS answered_handle
     FROM checks k
     JOIN users f ON f.id = k.from_user_id
     LEFT JOIN users t ON t.id = k.to_user_id
     LEFT JOIN users a ON a.id = k.answered_by
     WHERE k.id = ?`,
  ).bind(String(id ?? '')).first();
  if (!check) fail(404, 'no_such_check', "That check doesn't exist.");
  if (check.status === 'pending' && check.expires_at < now()) {
    await env.DB.prepare("UPDATE checks SET status = 'expired' WHERE id = ? AND status = 'pending'").bind(check.id).run();
    check.status = 'expired';
  }
  return check;
}

function checkView(env, check, viewer) {
  const role = viewer?.id === check.from_user_id ? 'from' : viewer && (check.to_user_id ? viewer.id === check.to_user_id : true) ? 'to' : 'viewer';
  const view = {
    id: check.id,
    role,
    from: check.from_handle,
    to: check.to_handle,
    status: check.status,
    createdAt: check.created_at,
    expiresAt: check.expires_at,
    answeredAt: check.answered_at,
    answeredBy: check.answered_handle,
    attemptsLeft: Math.max(0, MAX_CODE_ATTEMPTS - check.attempts),
  };
  if (role === 'from') {
    Object.assign(view, { code: check.code, link: `${env.ORIGIN}/c/${check.id}#${check.code}`, keyType: check.key_type, receipt: check.receipt });
  }
  if (role === 'to' && check.answered_by === viewer.id) view.receipt = check.receipt;
  return view;
}

function canAnswer(check, viewer) {
  if (check.from_user_id === viewer.id) fail(400, 'own_check', "You can't answer your own check.");
  if (check.to_user_id && check.to_user_id !== viewer.id) fail(403, 'not_for_you', `This check is for @${check.to_handle}.`);
  if (check.status !== 'pending') fail(409, 'not_pending', `This check is already ${check.status}.`);
}

async function spendAttempt(env, check, code) {
  if (safeEqual(normalizeCode(code), check.code)) return;
  const attempts = check.attempts + 1;
  const status = attempts >= MAX_CODE_ATTEMPTS ? 'failed' : 'pending';
  await env.DB.prepare('UPDATE checks SET attempts = ?, status = ? WHERE id = ?').bind(attempts, status, check.id).run();
  if (status === 'failed') fail(400, 'too_many_attempts', 'Too many wrong codes. This check has failed.');
  fail(400, 'wrong_code', `Those words don't match. ${MAX_CODE_ATTEMPTS - attempts} tries left.`);
}

app.post('/api/checks', async (c) => {
  const session = await requireSession(c);
  const me = session.user;
  const { to } = await body(c);
  let target = null;
  if (to) {
    target = await userByHandle(c.env, to);
    const allowed = await canChallenge(c.env, me, target);
    if (!allowed.ok) fail(403, 'not_allowed', allowed.reason);
    await rateLimit(c.env, `check:${me.id}:${target.id}`, 3, HOUR);
  }
  await rateLimit(c.env, `check:${me.id}`, 30, DAY);
  const t = now();
  const id = randomId(12);
  const code = newCode();
  await c.env.DB.prepare('INSERT INTO checks (id, from_user_id, to_user_id, code, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(id, me.id, target?.id ?? null, code, t, t + CHECK_TTL_MS).run();
  if (target) {
    c.executionCtx.waitUntil(notifyUser(c.env, target.id, {
      title: `@${me.handle} wants you to prove you're human`,
      body: 'Open to answer. It expires in 10 minutes.',
      url: `/c/${id}`,
      tag: id,
    }));
  }
  return c.json(checkView(c.env, await loadCheck(c.env, id), me));
});

app.get('/api/checks', async (c) => {
  const session = await requireSession(c);
  const me = session.user.id;
  const t = now();
  const select = `SELECT k.*, f.handle AS from_handle, t.handle AS to_handle, a.handle AS answered_handle
    FROM checks k JOIN users f ON f.id = k.from_user_id LEFT JOIN users t ON t.id = k.to_user_id LEFT JOIN users a ON a.id = k.answered_by`;
  const incoming = await c.env.DB.prepare(`${select} WHERE k.to_user_id = ? AND k.status = 'pending' AND k.expires_at > ? ORDER BY k.created_at DESC`).bind(me, t).all();
  const recent = await c.env.DB.prepare(`${select} WHERE k.from_user_id = ? OR k.to_user_id = ? OR k.answered_by = ? ORDER BY k.created_at DESC LIMIT 20`).bind(me, me, me).all();
  const settle = (k) => (k.status === 'pending' && k.expires_at < t ? { ...k, status: 'expired' } : k);
  return c.json({
    incoming: incoming.results.map((k) => checkView(c.env, k, session.user)),
    recent: recent.results.map((k) => checkView(c.env, settle(k), session.user)),
  });
});

app.get('/api/checks/:id', async (c) => {
  const check = await loadCheck(c.env, c.req.param('id'));
  const session = await currentSession(c);
  return c.json(checkView(c.env, check, session?.user));
});

app.post('/api/checks/:id/begin', async (c) => {
  const session = await requireSession(c);
  const check = await loadCheck(c.env, c.req.param('id'));
  canAnswer(check, session.user);
  await spendAttempt(c.env, check, (await body(c)).code);
  const options = await authenticationOptions(c.env, session.user.id);
  const ceremonyId = await startCeremony(c.env, { purpose: 'answer', challenge: options.challenge, userId: session.user.id, ref: check.id });
  return c.json({ ceremonyId, options });
});

app.post('/api/checks/:id/finish', async (c) => {
  const session = await requireSession(c);
  const me = session.user;
  const { ceremonyId, code, response } = await body(c);
  const ceremony = await takeCeremony(c.env, ceremonyId, 'answer');
  const check = await loadCheck(c.env, c.req.param('id'));
  if (ceremony.ref !== check.id || ceremony.user_id !== me.id) fail(403, 'wrong_check', "That confirmation doesn't belong to this check.");
  canAnswer(check, me);
  if (!safeEqual(normalizeCode(code), check.code)) fail(400, 'wrong_code', "Those words don't match.");
  const { deviceType } = await verifyAssertion(c.env, ceremony, response, { userId: me.id });

  const t = now();
  const keyKind = deviceType === 'singleDevice' ? 'device' : 'synced';
  const receipt = await signReceipt(c.env, {
    iss: c.env.ORIGIN,
    typ: 'human-check',
    jti: check.id,
    sub: me.handle,
    aud: check.from_handle,
    iat: Math.floor(t / 1000),
    result: 'passed',
    uv: true,
    code_matched: true,
    key: keyKind,
    sent_at: Math.floor(check.created_at / 1000),
  });
  const update = await c.env.DB.prepare(
    "UPDATE checks SET status = 'passed', answered_at = ?, answered_by = ?, key_type = ?, receipt = ? WHERE id = ? AND status = 'pending'",
  ).bind(t, me.id, keyKind, receipt, check.id).run();
  if (!update.meta.changes) fail(409, 'not_pending', 'This check was already answered.');
  await c.env.DB.prepare('UPDATE users SET last_check_at = ?, checks_passed = checks_passed + 1 WHERE id = ?').bind(t, me.id).run();
  await c.env.DB.prepare('UPDATE sessions SET verified_at = ? WHERE token_hash = ?').bind(t, session.tokenHash).run();

  c.executionCtx.waitUntil(notifyUser(c.env, check.from_user_id, {
    title: `@${me.handle} passed your check`,
    body: 'A live face confirmed it on their phone just now.',
    url: `/c/${check.id}`,
    tag: check.id,
  }));
  return c.json(checkView(c.env, await loadCheck(c.env, check.id), me));
});

app.post('/api/checks/:id/decline', async (c) => {
  const session = await requireSession(c);
  const check = await loadCheck(c.env, c.req.param('id'));
  if (check.to_user_id !== session.user.id) fail(403, 'not_for_you', "This check isn't addressed to you.");
  await c.env.DB.prepare("UPDATE checks SET status = 'declined', answered_at = ? WHERE id = ? AND status = 'pending'").bind(now(), check.id).run();
  return c.json(checkView(c.env, await loadCheck(c.env, check.id), session.user));
});

// ---------- Notifications ----------

app.post('/api/push', async (c) => {
  const session = await requireSession(c);
  const { endpoint, keys } = await body(c);
  if (!/^https:\/\//.test(endpoint ?? '') || !keys?.p256dh || !keys?.auth) fail(400, 'bad_subscription', "Your browser sent an invalid notification setup.");
  await c.env.DB.prepare('INSERT OR REPLACE INTO push_subscriptions (endpoint, user_id, p256dh, auth, created_at) VALUES (?, ?, ?, ?, ?)')
    .bind(endpoint, session.user.id, keys.p256dh, keys.auth, now()).run();
  return c.json({ ok: true });
});

app.delete('/api/push', async (c) => {
  const session = await requireSession(c);
  const { endpoint } = await body(c);
  await c.env.DB.prepare('DELETE FROM push_subscriptions WHERE endpoint = ? AND user_id = ?').bind(String(endpoint ?? ''), session.user.id).run();
  return c.json({ ok: true });
});

// ---------- QR codes for sharing in person ----------

app.get('/api/qr', (c) => {
  const path = c.req.query('path') ?? '/';
  if (!/^\/[A-Za-z0-9_/@#.-]{0,200}$/.test(path)) fail(400, 'bad_path', 'QR codes can only point to this site.');
  const svg = renderSVG(`${c.env.ORIGIN}${path}`, { border: 2, whiteColor: '#ffffff', blackColor: '#111111' });
  return c.body(svg, 200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' });
});

app.all('/api/*', () => fail(404, 'not_found', 'No such endpoint.'));

export default {
  fetch: app.fetch,
  async scheduled(_event, env) {
    const t = now();
    await env.DB.batch([
      env.DB.prepare('DELETE FROM ceremonies WHERE expires_at < ?').bind(t),
      env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(t),
      env.DB.prepare('DELETE FROM rate_events WHERE at < ?').bind(t - 2 * DAY),
      env.DB.prepare('DELETE FROM checks WHERE created_at < ?').bind(t - 30 * DAY),
    ]);
  },
};
