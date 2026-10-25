# I'm Human

**Prove you're human. Anywhere.** Try it: **https://imhuman.milomitm.workers.dev**

AI can now fake a voice, a face, and a whole conversation. I'm Human gives you a handle, like `@poopsocket123`, that anyone can ask you to prove. You glance at your phone, say three words back, and they see that a live human answered.

It works next to any channel (phone calls, DMs, dating apps, email), so it needs no deals with Apple, Google, or phone carriers. It's free, open source, and collects no names, emails, phone numbers, or photos.

## How it works

1. **Get a handle.** Signing up creates a passkey: a key sealed inside your phone's security chip that only unlocks with your face, fingerprint, or passcode. The server only ever sees the public half.
2. **Share it anywhere.** Say it on a call, put it in your bio, or show the QR code.
3. **Anyone can check you.** They send a check. On a call you just open the app; in a chat they send you a link.
4. **You answer with your face.** Your phone signs that exact check after confirming it's you, and only then shows you three random words (`album · puppet · meteor`).
5. **You read the words back.** The sender sees the same words (only after your face check), confirms they match, and gets **"@you is a live human"**.

The three words are what tie your handle to *this* conversation. If a scammer gives out someone else's handle, the real owner might pass the face check, but the scammer won't know the words. The sender never sees the words before the face check, so there's nothing to trick out of them.

Profiles show a freshness badge (**checked in today / this week / overdue**). A daily glance keeps it fresh. Exact times are never shown to others.

## What a pass proves, and what it doesn't

A pass proves:
- Someone unlocked the phone that owns that handle, within the last few minutes.
- That person read the three words back to the sender, so they're the one in the conversation.
- A bot or AI agent on a server can't answer on its own. It would need the phone *and* the person.

A pass does **not** prove:
- Who someone is in real life. "A live human" is not "your bank" or "your mom".
- That they wrote their own messages. A person can still read out an AI's script.
- That nobody is forcing them, or sitting next to them.
- Face versus passcode. Phones don't tell websites which one was used.
- One handle per person. This version has no passport or ID check, so one person can make several handles. Older handles with many passed checks are harder to fake.

## Security design

- **Passkeys (WebAuthn) with user verification required** on every sign-up, sign-in, check-in, and answer. Passkeys without face, fingerprint, or passcode are rejected.
- **Phishing-proof:** signatures are bound to this site's domain, and signatures made for any other site are refused.
- **Every confirmation is single-use:** each passkey prompt gets a server-side challenge that's deleted when used, so it can't be replayed.
- **Checks are bound to one person and one moment:** a check addressed to `@jordan` can only be answered by `@jordan`'s passkey, within 10 minutes. The words appear only after that face check, and the check passes only when the sender confirms they were read back. Neither side sees the words before the face check.
- **Signed receipts:** every passed check produces a standard JWT (ES256). Anyone can verify it with the public key at `/.well-known/jwks.json`, or on the `/verify` page, without trusting the site's screens.
- **Abuse limits:** one person can check another at most 3 times an hour (30 checks a day total). Everyone controls who can check them (anyone, only people they added, or nobody), and can block.
- **Sensitive changes need a fresh face check:** adding or removing a passkey, or deleting the account.
- **Deleted handles are retired forever,** so nobody can take over a handle people already trust.
- **Cookies are HttpOnly and SameSite.** Every state-changing request must come from the site's own origin. A strict Content Security Policy is set.
- **Alerts use standard Web Push (RFC 8291/8292),** implemented with WebCrypto and no third-party push service.

## Run it locally

You need Node 20+.

```bash
npm install
npm run setup      # creates signing keys in .dev.vars
npm run db:local   # creates the local database
npm run dev        # http://localhost:8787
```

In another terminal:

```bash
npm test
```

The tests drive the real server with a software passkey that makes genuine signatures. They cover the full check flow (face check, words read back, sender confirms), words that didn't match, replays, phishing-origin signatures, missing face check, rate limits, blocking, receipts, and push encryption.

Passkeys only work on `localhost` or a real HTTPS domain. To try it on your phone before deploying, deploy it (it's free).

## Deploy for free (Cloudflare)

Everything runs on Cloudflare's free tier: Workers, D1 database, static files, and cron. The only cost is a domain (a `.com` is about $10 a year at cost through Cloudflare Registrar).

> **Pick your final domain before real people sign up.** Passkeys are locked to the domain. If you move domains later, everyone's passkeys stop working.

1. Create a free Cloudflare account, then log in:
   ```bash
   npx wrangler login
   ```
2. Create the database, and paste the `database_id` it prints into `wrangler.jsonc`:
   ```bash
   npx wrangler d1 create humanid
   ```
3. In `wrangler.jsonc`, set `RP_ID` to your domain (`example.com`), `ORIGIN` to `https://example.com`, and `VAPID_SUBJECT` to a contact URL or `mailto:` address. (Your first deploy prints a free `*.workers.dev` address you can use until you have a domain.)
4. Create the tables:
   ```bash
   npx wrangler d1 migrations apply humanid --remote
   ```
5. Make production keys, upload them, and delete the file:
   ```bash
   npm run setup -- --production secrets.json
   npx wrangler secret bulk secrets.json
   rm secrets.json
   ```
6. Deploy:
   ```bash
   npm run deploy
   ```
7. In the Cloudflare dashboard, open the `imhuman` Worker, then Settings, then Domains & Routes, and add your domain as a Custom Domain.

## Build on it

Other sites and apps can use these public endpoints:

| Endpoint | What it returns |
|---|---|
| `GET /api/users/:handle` | Public profile: freshness, member since, passed checks (CORS enabled) |
| `GET /api/badge/:handle.svg` | A live badge image for websites and READMEs |
| `GET /.well-known/jwks.json` | Public key for verifying receipts |
| `/u/:handle` | Profile page with a "prove it" button |

Badge example:

```html
<a href="https://example.com/u/poopsocket123"><img src="https://example.com/api/badge/poopsocket123.svg" alt="@poopsocket123 on I'm Human"></a>
```

## Roadmap

- **One person, one handle (optional):** scan a passport chip with a zero-knowledge proof, so a handle can show "unique person" without revealing who.
- **Linked accounts:** prove your Instagram, X, email, and phone number belong to your handle, so a DM from a linked account shows your status.
- **Native apps:** keys that can't leave the device, plus Apple App Attest and Google Play Integrity to rule out emulators and fake cameras.
- **"Verify human" button:** a drop-in widget so any app can request a check in one tap.
- **Agent mode:** a labeled credential for AI agents acting on behalf of a verified human, separate from the human's own badge.

## Project layout

```
src/            Cloudflare Worker (API)
  index.js      routes: sign-up, sign-in, checks, contacts, profiles, alerts
  auth.js       passkeys, sessions, one-time ceremonies, rate limits
  push.js       Web Push encryption and VAPID
  receipts.js   signed receipts (ES256 JWT)
  words.js      the 256-word list for check codes
public/         the website (plain HTML, CSS, JS; no build step)
migrations/     database schema
test/           end-to-end tests and a software passkey
scripts/        key setup and icon generation
```

## License

MIT. See [LICENSE](LICENSE).
