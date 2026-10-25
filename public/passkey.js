// Thin wrapper over the browser's passkey API (WebAuthn): converts the server's JSON options
// into the binary form the browser wants, and the browser's answer back into JSON.

const enc = (buf) => {
  let s = '';
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const dec = (str) => {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '==='.slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
};

export const supported = () => Boolean(window.PublicKeyCredential && navigator.credentials);

function friendly(err) {
  if (err?.name === 'NotAllowedError') return new Error('Face check was cancelled or timed out.');
  if (err?.name === 'InvalidStateError') return new Error('This device already has a passkey for this handle.');
  if (err?.name === 'SecurityError') return new Error("Passkeys don't work on this address. Open the site from its real domain.");
  return err instanceof Error ? err : new Error(String(err));
}

export async function createPasskey(options) {
  const publicKey = {
    ...options,
    challenge: dec(options.challenge),
    user: { ...options.user, id: dec(options.user.id) },
    excludeCredentials: (options.excludeCredentials ?? []).map((c) => ({ ...c, id: dec(c.id) })),
  };
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey });
  } catch (err) {
    throw friendly(err);
  }
  return {
    id: cred.id,
    rawId: enc(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults?.() ?? {},
    response: {
      clientDataJSON: enc(cred.response.clientDataJSON),
      attestationObject: enc(cred.response.attestationObject),
      transports: cred.response.getTransports?.() ?? [],
    },
  };
}

export async function usePasskey(options) {
  const publicKey = {
    ...options,
    challenge: dec(options.challenge),
    allowCredentials: (options.allowCredentials ?? []).map((c) => ({ ...c, id: dec(c.id) })),
  };
  let cred;
  try {
    cred = await navigator.credentials.get({ publicKey });
  } catch (err) {
    throw friendly(err);
  }
  return {
    id: cred.id,
    rawId: enc(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults?.() ?? {},
    response: {
      clientDataJSON: enc(cred.response.clientDataJSON),
      authenticatorData: enc(cred.response.authenticatorData),
      signature: enc(cred.response.signature),
      userHandle: cred.response.userHandle ? enc(cred.response.userHandle) : undefined,
    },
  };
}

// Verifies a receipt (ES256 JWT) against the published keys, entirely in the browser.
export async function verifyReceipt(token, jwksUrl) {
  const parts = token.trim().split('.');
  if (parts.length !== 3) throw new Error("That doesn't look like a receipt.");
  const text = (s) => new TextDecoder().decode(dec(s));
  const header = JSON.parse(text(parts[0]));
  const claims = JSON.parse(text(parts[1]));
  const { keys } = await (await fetch(jwksUrl)).json();
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk || header.alg !== 'ES256') return { valid: false, claims, reason: 'Signed with a key this site does not publish.' };
  const key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    dec(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  return { valid, claims, reason: valid ? null : 'The signature does not match. This receipt was changed or forged.' };
}
