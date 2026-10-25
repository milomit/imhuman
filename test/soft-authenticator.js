// A software stand-in for a phone's passkey hardware. It produces real WebAuthn registrations and
// signatures (P-256, "none" attestation), so tests exercise the server's actual verification code.
// Works in Node and in a browser.

const te = new TextEncoder();

export const b64url = (bytes) => {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const concat = (...parts) => {
  const arrays = parts.map((p) => (p instanceof Uint8Array ? p : Uint8Array.from(p)));
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrays) {
    out.set(a, o);
    o += a.length;
  }
  return out;
};

const sha256 = async (data) => new Uint8Array(await crypto.subtle.digest('SHA-256', typeof data === 'string' ? te.encode(data) : data));

function cbor(value) {
  const out = [];
  const head = (major, n) => {
    if (n < 24) out.push((major << 5) | n);
    else if (n < 256) out.push((major << 5) | 24, n);
    else out.push((major << 5) | 25, n >> 8, n & 255);
  };
  const enc = (v) => {
    if (typeof v === 'number') v >= 0 ? head(0, v) : head(1, -1 - v);
    else if (typeof v === 'string') { const b = te.encode(v); head(3, b.length); out.push(...b); }
    else if (v instanceof Uint8Array) { head(2, v.length); out.push(...v); }
    else if (v instanceof Map) { head(5, v.size); for (const [k, x] of v) { enc(k); enc(x); } }
    else throw new Error(`cbor: unsupported value ${v}`);
  };
  enc(value);
  return Uint8Array.from(out);
}

function derInteger(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  let v = bytes.slice(i);
  if (v[0] & 0x80) v = concat([0], v);
  return concat([0x02, v.length], v);
}

const derSignature = (raw) => {
  const r = derInteger(raw.slice(0, 32));
  const s = derInteger(raw.slice(32));
  return concat([0x30, r.length + s.length], r, s);
};

export class SoftAuthenticator {
  // uv: whether the "phone" confirms the user (face/fingerprint). synced: behaves like a synced passkey.
  constructor({ origin, rpId, uv = true, synced = false }) {
    Object.assign(this, { origin, rpId, uv, synced });
    this.creds = new Map();
  }

  flags(extra = 0) {
    return 0x01 | (this.uv ? 0x04 : 0) | (this.synced ? 0x18 : 0) | extra;
  }

  async create(options) {
    const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey));
    const credId = crypto.getRandomValues(new Uint8Array(16));
    const id = b64url(credId);
    const coseKey = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, raw.slice(1, 33)], [-3, raw.slice(33)]]));
    const authData = concat(await sha256(options.rp?.id ?? this.rpId), [this.flags(0x40)], [0, 0, 0, 0], new Uint8Array(16), [0, credId.length], credId, coseKey);
    const clientData = te.encode(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin: this.origin, crossOrigin: false }));
    this.creds.set(id, { keys, userHandle: options.user.id });
    return {
      id,
      rawId: id,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64url(clientData),
        attestationObject: b64url(cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]))),
        transports: ['internal', 'hybrid'],
      },
    };
  }

  async get(options, { credentialId, origin } = {}) {
    const id = credentialId
      ?? options.allowCredentials?.map((c) => c.id).find((c) => this.creds.has(c))
      ?? [...this.creds.keys()][0];
    const cred = this.creds.get(id);
    if (!cred) throw new Error('No matching passkey on this soft authenticator');
    const authData = concat(await sha256(this.rpId), [this.flags()], [0, 0, 0, 0]);
    const clientData = te.encode(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin: origin ?? this.origin, crossOrigin: false }));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, cred.keys.privateKey, concat(authData, await sha256(clientData))));
    return {
      id,
      rawId: id,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64url(clientData),
        authenticatorData: b64url(authData),
        signature: b64url(derSignature(raw)),
        userHandle: cred.userHandle,
      },
    };
  }
}
