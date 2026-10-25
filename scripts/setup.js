// Creates the signing keys the server needs and writes them to .dev.vars for local development.
// For production, it prints the `wrangler secret put` commands to run with the same values.
import { existsSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const b64url = (buf) => Buffer.from(buf).toString('base64url');

async function p256() {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

const receipt = await p256();
const receiptJwk = await crypto.subtle.exportKey('jwk', receipt.privateKey);
receiptJwk.kid = `hid-${new Date().toISOString().slice(0, 10)}-${b64url(crypto.getRandomValues(new Uint8Array(4)))}`;

const vapid = await p256();
const vapidJwk = await crypto.subtle.exportKey('jwk', vapid.privateKey);
const vapidPublic = b64url(await crypto.subtle.exportKey('raw', vapid.publicKey));

const vars = {
  RECEIPT_KEY: JSON.stringify(receiptJwk),
  VAPID_PUBLIC_KEY: vapidPublic,
  VAPID_PRIVATE_KEY: JSON.stringify(vapidJwk),
};

const force = process.argv.includes('--force');
if (existsSync('.dev.vars') && !force) {
  console.log('.dev.vars already exists. Run `npm run setup -- --force` to replace it.');
} else {
  writeFileSync('.dev.vars', Object.entries(vars).map(([k, v]) => `${k}='${v}'`).join('\n') + '\n');
  console.log('Wrote .dev.vars with fresh keys for local development.');
}

if (process.argv.includes('--print')) {
  console.log('\nFor production, run each of these and paste the value when asked:\n');
  for (const [k, v] of Object.entries(vars)) console.log(`npx wrangler secret put ${k}\n  ${v}\n`);
}
