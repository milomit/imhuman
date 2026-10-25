// Creates the signing keys the server needs and writes them to .dev.vars for local development.
// With `--production <file>`, writes fresh keys to a JSON file for `npx wrangler secret bulk <file>` instead.
import { existsSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const b64url = (buf) => Buffer.from(buf).toString('base64url');

async function p256() {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

const receipt = await p256();
const receiptJwk = await crypto.subtle.exportKey('jwk', receipt.privateKey);
receiptJwk.kid = `imh-${new Date().toISOString().slice(0, 10)}-${b64url(crypto.getRandomValues(new Uint8Array(4)))}`;

const vapid = await p256();
const vapidJwk = await crypto.subtle.exportKey('jwk', vapid.privateKey);
const vapidPublic = b64url(await crypto.subtle.exportKey('raw', vapid.publicKey));

const vars = {
  RECEIPT_KEY: JSON.stringify(receiptJwk),
  VAPID_PUBLIC_KEY: vapidPublic,
  VAPID_PRIVATE_KEY: JSON.stringify(vapidJwk),
};

const prodIndex = process.argv.indexOf('--production');
if (prodIndex !== -1) {
  const file = process.argv[prodIndex + 1] ?? 'secrets.json';
  writeFileSync(file, JSON.stringify(vars, null, 2), { mode: 0o600 });
  console.log(`Wrote production keys to ${file}. Upload with \`npx wrangler secret bulk ${file}\`, then delete the file.`);
  process.exit(0);
}

const local = { RP_ID: 'localhost', ORIGIN: 'http://localhost:8787', ...vars };
if (existsSync('.dev.vars') && !process.argv.includes('--force')) {
  console.log('.dev.vars already exists. Run `npm run setup -- --force` to replace it.');
} else {
  writeFileSync('.dev.vars', Object.entries(local).map(([k, v]) => `${k}='${v}'`).join('\n') + '\n');
  console.log('Wrote .dev.vars with fresh keys for local development.');
}
