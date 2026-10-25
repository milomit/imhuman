const enc = new TextEncoder();

export function b64url(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64url(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '==='.slice((s.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function randomId(bytes = 16) {
  return b64url(randomBytes(bytes));
}

export async function sha256(data) {
  const bytes = typeof data === 'string' ? enc.encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function sha256b64(data) {
  return b64url(await sha256(data));
}

export function concat(...parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// Constant-time string comparison, so response timing can't leak how much of a code matched.
export function safeEqual(a, b) {
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

export const now = () => Date.now();

export const DAY = 24 * 60 * 60 * 1000;

// What other people see about how recently someone proved they're here. Exact times stay private.
export function freshness(lastCheckAt, at = now()) {
  if (!lastCheckAt) return 'never';
  const age = at - lastCheckAt;
  if (age < DAY) return 'today';
  if (age < 7 * DAY) return 'week';
  return 'overdue';
}

export class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export const fail = (status, code, message) => {
  throw new HttpError(status, code, message);
};

const RESERVED = new Set([
  'admin', 'api', 'app', 'about', 'help', 'home', 'how', 'join', 'login', 'logout', 'me', 'settings',
  'support', 'verify', 'official', 'staff', 'team', 'root', 'system', 'security', 'humanid', 'human', 'imhuman', 'im_human', 'iamhuman',
  'null', 'undefined', 'www',
]);

export function normalizeHandle(raw) {
  return String(raw ?? '').trim().replace(/^@/, '').toLowerCase();
}

export function handleProblem(handle) {
  if (!/^[a-z0-9_]{3,20}$/.test(handle)) return 'Use 3 to 20 letters, numbers, or underscores.';
  if (RESERVED.has(handle)) return 'That handle is reserved.';
  return null;
}
