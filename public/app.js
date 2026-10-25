import { supported, createPasskey, usePasskey, verifyReceipt } from '/passkey.js';

// ---------- Small helpers ----------

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
const app = $('#app');

let me = null;
let config = { origin: location.origin, pushKey: null };
let cleanups = [];

const store = {
  get: (k) => { try { return sessionStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { sessionStorage.setItem(k, v); } catch {} },
  del: (k) => { try { sessionStorage.removeItem(k); } catch {} },
};

async function api(method, path, data) {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: method === 'GET' ? {} : { 'Content-Type': 'application/json' },
    body: method === 'GET' ? undefined : JSON.stringify(data ?? {}),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(json.message || 'Something went wrong. Try again.');
    err.code = json.error;
    err.status = res.status;
    throw err;
  }
  return json;
}

let toastTimer;
function toast(message, bad = false) {
  const el = $('#toast');
  el.textContent = message;
  el.className = `show${bad ? ' bad' : ''}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = ''; }, 3200);
}

function every(ms, fn) {
  const id = setInterval(fn, ms);
  cleanups.push(() => clearInterval(id));
}

// Runs an async action from a button, with a busy state and friendly errors.
async function busy(button, fn) {
  const label = button?.innerHTML;
  if (button) { button.disabled = true; button.innerHTML = 'One moment…'; }
  try {
    return await fn();
  } catch (err) {
    if (err.status === 401) { me = null; navigate('/'); }
    toast(err.message, true);
    return undefined;
  } finally {
    if (button && button.isConnected) { button.disabled = false; button.innerHTML = label; }
  }
}

async function copy(text, what = 'Copied') {
  try {
    await navigator.clipboard.writeText(text);
    toast(what);
  } catch {
    prompt('Copy this:', text);
  }
}

const ago = (t) => {
  if (!t) return 'never';
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 45) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} hr ago`;
  if (s < 172800) return 'yesterday';
  return new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
};

const clock = (ms) => {
  const s = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
};

const span = (ms) => {
  const s = Math.max(1, Math.round(ms / 1000));
  if (s < 90) return `${s} second${s === 1 ? '' : 's'}`;
  return `${Math.round(s / 60)} minutes`;
};

const FRESH = { today: 'Checked in today', week: 'Checked in this week', overdue: 'Check-in overdue', never: 'Never checked in' };
const pill = (f) => `<span class="pill ${esc(f)}">${FRESH[f] ?? esc(f)}</span>`;
const KEY = {
  device: 'Their passkey lives on one device only.',
  synced: 'Their passkey syncs across their devices (like iCloud Keychain or Google Password Manager).',
  mixed: 'They have passkeys on more than one device.',
  none: '',
};
const words = (code) => String(code ?? '').toLowerCase().split(/[^a-z]+/).filter(Boolean);
const showCode = (code) => words(code).join(' · ');
const isIOS = () => /iPhone|iPad|iPod/.test(navigator.userAgent);
const isStandalone = () => window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;

function dec(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '==='.slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
}

// ---------- Passkey flows ----------

async function ceremony(begin, finish, extra = {}, kind = 'get') {
  if (!supported()) throw new Error("This browser can't use passkeys. Try Safari on iPhone or Chrome on Android.");
  const { ceremonyId, options } = await api('POST', begin, extra);
  const response = kind === 'create' ? await createPasskey(options) : await usePasskey(options);
  return api('POST', finish, { ...extra, ceremonyId, response });
}

async function refreshMe() {
  me = await api('GET', '/api/me').catch(() => null);
  return me;
}

async function signIn(button) {
  const done = await busy(button, () => ceremony('/api/login/begin', '/api/login/finish'));
  if (!done) return;
  await refreshMe();
  toast(`Signed in as @${me.handle}`);
  const next = store.get('hid-next');
  store.del('hid-next');
  navigate(next || '/home');
}

async function checkIn() {
  me = await ceremony('/api/presence/begin', '/api/presence/finish');
  return me;
}

// Sensitive changes need a face check from the last few minutes; do one and retry if needed.
async function withFreshFace(fn) {
  try {
    return await fn();
  } catch (err) {
    if (err.code !== 'reverify') throw err;
    await checkIn();
    return fn();
  }
}

// ---------- Notifications ----------

function pushAvailability() {
  if (!config.pushKey) return 'server-off';
  if (!('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) {
    return isIOS() && !isStandalone() ? 'ios-install' : 'unsupported';
  }
  if (Notification.permission === 'denied') return 'denied';
  return 'ok';
}

async function pushSubscription() {
  if (!('serviceWorker' in navigator)) return null;
  const reg = await navigator.serviceWorker.getRegistration();
  return reg?.pushManager ? reg.pushManager.getSubscription() : null;
}

async function enablePush() {
  const reg = await navigator.serviceWorker.register('/sw.js');
  await navigator.serviceWorker.ready;
  const permission = await Notification.requestPermission();
  if (permission !== 'granted') throw new Error('Alerts were not allowed. You can turn them on in your browser settings.');
  const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: dec(config.pushKey) });
  await api('POST', '/api/push', sub.toJSON());
}

async function disablePush() {
  const sub = await pushSubscription();
  if (!sub) return;
  await api('DELETE', '/api/push', { endpoint: sub.endpoint });
  await sub.unsubscribe();
}

// ---------- Router ----------

const routes = [
  [/^\/$/, viewLanding],
  [/^\/join$/, viewJoin],
  [/^\/home$/, viewHome],
  [/^\/u\/([A-Za-z0-9_]{1,30})$/, viewProfile],
  [/^\/c\/([A-Za-z0-9_-]{8,40})$/, viewCheck],
  [/^\/settings$/, viewSettings],
  [/^\/verify$/, viewVerify],
  [/^\/how$/, viewHow],
];

function navigate(path, replace = false) {
  history[replace ? 'replaceState' : 'pushState']({}, '', path);
  render();
}

document.addEventListener('click', (e) => {
  const a = e.target.closest('a[data-link]');
  if (!a || e.metaKey || e.ctrlKey || e.shiftKey) return;
  e.preventDefault();
  navigate(a.getAttribute('href'));
});
window.addEventListener('popstate', render);

function renderNav() {
  const path = location.pathname;
  const link = (href, text) => `<a href="${href}" data-link class="${path === href ? 'on' : ''}">${text}</a>`;
  $('#nav').innerHTML = me
    ? `${link('/home', `@${esc(me.handle)}`)}${link('/settings', 'Settings')}`
    : `${link('/how', 'How it works')}<a href="#" id="nav-signin">Sign in</a>`;
  $('#nav-signin')?.addEventListener('click', (e) => { e.preventDefault(); signIn(); });
}

async function render() {
  cleanups.forEach((fn) => fn());
  cleanups = [];
  window.scrollTo(0, 0);
  renderNav();
  const path = location.pathname.replace(/\/+$/, '') || '/';
  for (const [pattern, view] of routes) {
    const match = path.match(pattern);
    if (!match) continue;
    try {
      await view(...match.slice(1));
    } catch (err) {
      if (err.status === 401) { me = null; navigate('/', true); return; }
      app.innerHTML = `<div class="card warn"><h2>That didn't work</h2><p>${esc(err.message)}</p><a class="btn" href="/" data-link>Go home</a></div>`;
    }
    return;
  }
  app.innerHTML = '<h1>Not here</h1><p class="muted">That page doesn\'t exist.</p><a class="btn" href="/" data-link>Go home</a>';
}

function requireMe() {
  if (me) return true;
  store.set('hid-next', location.pathname + location.hash);
  navigate('/', true);
  return false;
}

// ---------- Views ----------

function viewLanding() {
  if (me) return navigate('/home', true);
  app.innerHTML = `
    <h1>Prove you're human. Anywhere.</h1>
    <p class="lead">AI can fake a voice, a face, and a whole conversation. Human ID gives you a handle anyone can ask you to prove, and your face answers.</p>
    <ol class="steps">
      <li><strong>Get a handle.</strong> Like @poopsocket123. No name, no email, no photo.</li>
      <li><strong>Share it anywhere.</strong> On a call, in a DM, in your bio.</li>
      <li><strong>Anyone can check you.</strong> You glance at your phone, say three words back, and they see a live human answered.</li>
    </ol>
    ${supported() ? '' : '<div class="card warn"><p>This browser can\'t use passkeys. Open this page in Safari on iPhone or Chrome on Android.</p></div>'}
    <div class="stack">
      <a class="btn primary block" href="/join" data-link>Create your Human ID</a>
      <button class="block" id="signin">I already have one</button>
    </div>
    <p class="faint center pad">Your face never leaves your phone. <a href="/how" data-link>How it works, and what it can't do</a></p>`;
  $('#signin').addEventListener('click', (e) => signIn(e.currentTarget));
}

function viewJoin() {
  if (me) return navigate('/home', true);
  app.innerHTML = `
    <h1>Pick your handle</h1>
    <p class="muted">This is what you'll give people. It can't be changed later, so pick one you like.</p>
    <form id="join" class="card" novalidate>
      <label for="handle">Handle</label>
      <div class="at"><input id="handle" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="20" placeholder="poopsocket123" required></div>
      <p class="field-note" id="note">3 to 20 letters, numbers, or underscores.</p>
      <button class="primary block" id="go">Create with Face ID</button>
    </form>
    <p class="faint">Your phone will ask for Face ID, your fingerprint, or your passcode. That creates a passkey: a key sealed inside your phone that only you can unlock. We never see your face.</p>`;
  const input = $('#handle');
  const note = $('#note');
  let timer;
  input.addEventListener('input', () => {
    input.value = input.value.toLowerCase().replace(/[^a-z0-9_]/g, '');
    clearTimeout(timer);
    note.className = 'field-note';
    note.textContent = input.value.length < 3 ? '3 to 20 letters, numbers, or underscores.' : 'Checking…';
    if (input.value.length < 3) return;
    timer = setTimeout(async () => {
      const value = input.value;
      const res = await api('GET', `/api/handles/${encodeURIComponent(value)}`).catch(() => null);
      if (!res || input.value !== value) return;
      note.className = `field-note ${res.available ? 'good' : 'bad'}`;
      note.textContent = res.available ? `@${res.handle} is yours if you want it.` : res.problem;
    }, 300);
  });
  input.focus();
  $('#join').addEventListener('submit', async (e) => {
    e.preventDefault();
    const handle = input.value;
    const done = await busy($('#go'), () => ceremony('/api/signup/begin', '/api/signup/finish', { handle }, 'create'));
    if (!done) return;
    await refreshMe();
    toast(`Welcome, @${me.handle}`);
    const next = store.get('hid-next');
    store.del('hid-next');
    navigate(next || '/home');
  });
}

async function sendCheck(to, button) {
  const check = await busy(button, () => api('POST', '/api/checks', { to: to || undefined }));
  if (check) navigate(`/c/${check.id}`);
}

function checkLine(k) {
  const STATUS = { passed: ['passed', 'today'], pending: ['waiting', ''], declined: ['declined', 'overdue'], expired: ['expired', ''], failed: ['failed', 'overdue'] };
  const [word, cls] = STATUS[k.status] ?? [k.status, ''];
  const who = k.role === 'from'
    ? `You checked ${k.to ? `@${esc(k.to)}` : k.answeredBy ? `@${esc(k.answeredBy)} (link)` : 'an open link'}`
    : `@${esc(k.from)} checked you`;
  return `<li><a class="grow" href="/c/${esc(k.id)}" data-link>${who}<br><span class="faint">${ago(k.createdAt)}</span></a><span class="pill ${cls}">${word}</span></li>`;
}

async function viewHome() {
  if (!requireMe()) return;
  await refreshMe();
  const [checks, contacts] = await Promise.all([api('GET', '/api/checks'), api('GET', '/api/contacts')]);
  const profileUrl = `${config.origin}/u/${me.handle}`;
  const push = pushAvailability();
  const subscribed = push === 'ok' ? await pushSubscription().catch(() => null) : null;

  app.innerHTML = `
    <section class="card">
      <p class="big-handle">@${esc(me.handle)}</p>
      <div class="row wrap">${pill(me.freshness)}<span class="faint">Last check-in ${ago(me.lastCheckAt)}</span></div>
      <div class="stack">
        <button class="${me.freshness === 'today' ? '' : 'primary'} block" id="checkin">${me.freshness === 'today' ? 'Check in again' : 'Check in now'}</button>
        <div class="linkbox" id="mylink">${esc(profileUrl)}</div>
        <div class="row">
          <button class="small grow" id="copy-link">Copy link</button>
          <button class="small grow" id="show-qr">Show QR code</button>
        </div>
        <img class="qr hidden" id="qr" alt="QR code for your Human ID page">
      </div>
    </section>

    ${checks.incoming.length ? `
    <section class="card warn">
      <h2>Waiting for you</h2>
      <ul class="list">${checks.incoming.map((k) => `
        <li><span class="grow">@${esc(k.from)} wants you to prove you're human<br><span class="faint" data-expires="${k.expiresAt}"></span></span>
        <a class="btn small primary" href="/c/${esc(k.id)}" data-link>Answer</a></li>`).join('')}
      </ul>
    </section>` : ''}

    <section class="card">
      <h2>Ask someone to prove it</h2>
      <form id="send" class="row" novalidate>
        <div class="at grow"><input id="to" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" placeholder="their handle"></div>
        <button class="primary" id="send-btn">Send</button>
      </form>
      <p class="faint">Don't know their handle? Leave it empty to get a link anyone can answer.</p>
    </section>

    ${push === 'ok' && !subscribed ? `
    <section class="card">
      <h3>Get alerts when someone checks you</h3>
      <p class="muted small">Otherwise you'll only see checks when you open this page.</p>
      <button class="small" id="push-on">Turn on alerts</button>
    </section>` : ''}
    ${push === 'ios-install' ? `
    <section class="card">
      <h3>Want alerts on iPhone?</h3>
      <p class="muted small">Tap the Share button, then "Add to Home Screen". Open Human ID from there and turn on alerts.</p>
    </section>` : ''}

    <section class="card">
      <h2>Your people</h2>
      ${contacts.length ? `<ul class="list">${contacts.map((p) => `
        <li><a class="grow" href="/u/${esc(p.handle)}" data-link><span class="handle">@${esc(p.handle)}</span><br>${pill(p.freshness)}</a>
        <button class="small" data-check="${esc(p.handle)}">Check</button></li>`).join('')}</ul>`
        : '<p class="muted small">Add the people you talk to, so you can check them in one tap.</p>'}
      <form id="add" class="row" novalidate>
        <div class="at grow"><input id="add-handle" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" placeholder="add a handle"></div>
        <button id="add-btn">Add</button>
      </form>
    </section>

    ${checks.recent.length ? `
    <section class="card">
      <h2>Recent checks</h2>
      <ul class="list">${checks.recent.map(checkLine).join('')}</ul>
    </section>` : ''}`;

  const tick = () => $$('[data-expires]').forEach((el) => { el.textContent = `Expires in ${clock(Number(el.dataset.expires) - Date.now())}`; });
  tick();
  every(1000, tick);

  $('#checkin').addEventListener('click', async (e) => {
    if (await busy(e.currentTarget, checkIn)) { toast('Checked in. Your badge is fresh.'); render(); }
  });
  $('#copy-link').addEventListener('click', () => copy(profileUrl, 'Link copied'));
  $('#show-qr').addEventListener('click', (e) => {
    const qr = $('#qr');
    if (!qr.src) qr.src = `/api/qr?path=${encodeURIComponent(`/u/${me.handle}`)}`;
    qr.classList.toggle('hidden');
    e.currentTarget.textContent = qr.classList.contains('hidden') ? 'Show QR code' : 'Hide QR code';
  });
  $('#send').addEventListener('submit', (e) => {
    e.preventDefault();
    sendCheck($('#to').value.trim(), $('#send-btn'));
  });
  $$('[data-check]').forEach((b) => b.addEventListener('click', () => sendCheck(b.dataset.check, b)));
  $('#add').addEventListener('submit', async (e) => {
    e.preventDefault();
    const handle = $('#add-handle').value.trim();
    if (!handle) return;
    if (await busy($('#add-btn'), () => api('POST', '/api/contacts', { handle }))) { toast(`Added @${handle.replace(/^@/, '')}`); render(); }
  });
  $('#push-on')?.addEventListener('click', async (e) => {
    if ((await busy(e.currentTarget, async () => { await enablePush(); return true; }))) { toast('Alerts are on'); render(); }
  });

  // Keep the inbox live while this page is open.
  let seen = checks.incoming.map((k) => k.id).join();
  every(5000, async () => {
    if (document.hidden) return;
    const latest = await api('GET', '/api/checks').catch(() => null);
    if (latest && latest.incoming.map((k) => k.id).join() !== seen) {
      seen = latest.incoming.map((k) => k.id).join();
      render();
    }
  });
}

async function viewCheck(id) {
  const fromLink = words(decodeURIComponent(location.hash.slice(1))).join('-');
  if (fromLink) {
    store.set(`hid-code-${id}`, fromLink);
    history.replaceState({}, '', `/c/${id}`);
  }
  const linkCode = fromLink || store.get(`hid-code-${id}`) || '';
  let check = await api('GET', `/api/checks/${id}`);

  const draw = () => {
    const left = () => check.expiresAt - Date.now();
    const target = check.to ? `@${esc(check.to)}` : 'whoever you send it to';

    if (check.role === 'from') {
      if (check.status === 'pending') {
        app.innerHTML = `
          <h1>Waiting for ${check.to ? `@${esc(check.to)}` : 'an answer'}</h1>
          <section class="card">
            <h3>On a call? Say these three words:</h3>
            <div class="code" id="words">${esc(showCode(check.code))}</div>
            <p class="muted small">${check.to ? `@${esc(check.to)} types them into Human ID and confirms with their face.` : 'They type them into Human ID and confirm with their face.'} Only the person who heard you can answer.</p>
          </section>
          <section class="card">
            <h3>In a chat? Send this link instead:</h3>
            <div class="linkbox">${esc(check.link)}</div>
            <div class="row" data-mt>
              <button class="small grow" id="copy">Copy link</button>
              ${navigator.share ? '<button class="small grow" id="share">Share</button>' : ''}
            </div>
          </section>
          <p class="status"><span class="dot"></span><span>Waiting for ${target}. Expires in <strong id="left">${clock(left())}</strong></span></p>`;
        $('#copy').addEventListener('click', () => copy(check.link, 'Link copied'));
        $('#share')?.addEventListener('click', () => navigator.share({ text: `Prove you're human: ${check.link}` }).catch(() => {}));
        every(1000, () => { const el = $('#left'); if (el) el.textContent = clock(left()); });
        return;
      }
      if (check.status === 'passed') {
        app.innerHTML = `
          <section class="card success">
            <h1>@${esc(check.answeredBy)} is a live human</h1>
            <p>Their phone confirmed their face, fingerprint, or passcode, and they gave your three words back, ${span(check.answeredAt - check.createdAt)} after you sent this.</p>
          </section>
          <section class="card">
            <ul class="facts">
              <li>The words matched: ${esc(showCode(check.code))}</li>
              <li>A fresh check on @${esc(check.answeredBy)}'s own phone</li>
              ${check.keyType ? `<li>${check.keyType === 'device' ? 'Their passkey lives on one device only' : 'Their passkey syncs across their devices'}</li>` : ''}
            </ul>
            <p class="faint" data-mt>This proves a real person had @${esc(check.answeredBy)}'s phone in hand just now. It doesn't prove who they are in real life. <a href="/how" data-link>What a pass means</a></p>
          </section>
          <div class="stack">
            <a class="btn block" href="/u/${esc(check.answeredBy)}" data-link>See @${esc(check.answeredBy)}'s page</a>
            <button class="block" id="receipt">Copy signed receipt</button>
            <a class="btn ghost block" href="/home" data-link>Done</a>
          </div>`;
        $('#receipt').addEventListener('click', () => copy(check.receipt, 'Receipt copied. Anyone can verify it at /verify'));
        return;
      }
      const WHY = {
        declined: [`${check.to ? `@${esc(check.to)}` : 'They'} declined`, "They chose not to answer. If they're asking you for something sensitive, hold off."],
        expired: ['No answer in time', 'They may just be away. Try again when they can glance at their phone.'],
        failed: ['Wrong words, too many times', "Someone tried to answer without the right words. That's a red flag."],
      };
      const [title, text] = WHY[check.status];
      app.innerHTML = `
        <section class="card warn"><h1>${title}</h1><p>${text}</p></section>
        <div class="stack">
          <button class="primary block" id="again">Send another check</button>
          <a class="btn ghost block" href="/home" data-link>Back home</a>
        </div>`;
      $('#again').addEventListener('click', (e) => sendCheck(check.to, e.currentTarget));
      return;
    }

    if (!me) {
      store.set('hid-next', `/c/${id}`);
      app.innerHTML = `
        <h1>@${esc(check.from)} wants ${check.to ? `@${esc(check.to)}` : 'you'} to prove you're human</h1>
        ${check.status === 'pending'
          ? `<p class="muted">It takes a few seconds: sign in, glance at your phone, done. Expires in <strong id="left">${clock(left())}</strong>.</p>
             <div class="stack">
               <button class="primary block" id="signin">Sign in to answer</button>
               ${check.to ? '' : '<a class="btn block" href="/join" data-link>Create a Human ID to answer</a>'}
             </div>`
          : `<div class="card"><p>This check is ${esc(check.status)}.</p></div>`}`;
      $('#signin')?.addEventListener('click', (e) => signIn(e.currentTarget));
      if (check.status === 'pending') every(1000, () => { const el = $('#left'); if (el) el.textContent = clock(left()); });
      return;
    }

    if (check.role === 'viewer') {
      app.innerHTML = `<section class="card warn"><h1>This check is for @${esc(check.to)}</h1><p>You're signed in as @${esc(me.handle)}. Only @${esc(check.to)} can answer it.</p></section>`;
      return;
    }

    if (check.status === 'passed' && check.answeredBy === me.handle) {
      app.innerHTML = `
        <section class="card success"><h1>Done</h1><p>@${esc(check.from)} can now see that you passed.</p></section>
        <div class="stack">
          <button class="block" id="receipt">Copy signed receipt</button>
          <a class="btn ghost block" href="/home" data-link>Back home</a>
        </div>`;
      $('#receipt').addEventListener('click', () => copy(check.receipt, 'Receipt copied'));
      return;
    }

    if (check.status !== 'pending') {
      app.innerHTML = `<section class="card"><h1>This check is ${esc(check.status)}</h1><p class="muted">Nothing left to do here.</p><a class="btn" href="/home" data-link>Back home</a></section>`;
      return;
    }

    app.innerHTML = `
      <h1>@${esc(check.from)} wants you to prove you're human</h1>
      <form id="answer" class="card" novalidate>
        ${linkCode
          ? '<p class="good small">The three words came with your link.</p>'
          : `<label for="code">The three words @${esc(check.from)} told you</label>
             <input id="code" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" placeholder="maple rocket tiger">`}
        <p class="field-note" id="code-note"></p>
        <button class="primary block" id="go">Answer with Face ID</button>
      </form>
      <p class="status">Expires in <strong id="left">${clock(left())}</strong></p>
      ${check.to ? '<button class="ghost block" id="decline">Decline</button>' : ''}
      <p class="faint">@${esc(check.from)} will see that @${esc(me.handle)} answered. Nothing else about you is shared.</p>`;
    every(1000, () => { const el = $('#left'); if (el) el.textContent = clock(left()); });
    $('#answer').addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = linkCode || words($('#code').value).join('-');
      const note = $('#code-note');
      if (words(code).length !== 3) { note.className = 'field-note bad'; note.textContent = 'Enter all three words.'; return; }
      note.textContent = '';
      try {
        $('#go').disabled = true;
        check = await ceremony(`/api/checks/${id}/begin`, `/api/checks/${id}/finish`, { code });
        store.del(`hid-code-${id}`);
        await refreshMe();
        draw();
      } catch (err) {
        if (err.code === 'wrong_code' || err.code === 'too_many_attempts') {
          note.className = 'field-note bad';
          note.textContent = err.message;
          if (err.code === 'too_many_attempts') { check = await api('GET', `/api/checks/${id}`); setTimeout(draw, 1500); }
        } else {
          toast(err.message, true);
        }
      } finally {
        if ($('#go')) $('#go').disabled = false;
      }
    });
    $('#decline')?.addEventListener('click', async (e) => {
      const res = await busy(e.currentTarget, () => api('POST', `/api/checks/${id}/decline`));
      if (res) { check = res; draw(); }
    });
  };

  draw();
  if (check.status === 'pending') {
    every(2000, async () => {
      if (document.hidden) return;
      const fresh = await api('GET', `/api/checks/${id}`).catch(() => null);
      if (fresh && fresh.status !== check.status) {
        check = fresh;
        draw();
      }
    });
  }
}

async function viewProfile(rawHandle) {
  const handle = rawHandle.toLowerCase();
  let p;
  try {
    p = await api('GET', `/api/users/${encodeURIComponent(handle)}`);
  } catch (err) {
    if (err.status !== 404) throw err;
    app.innerHTML = `<h1>@${esc(handle)} isn't a Human ID</h1><p class="muted">Nobody has that handle. If someone told you it's theirs, be careful.</p>`;
    return;
  }
  const since = new Date(`${p.since}-01T00:00:00`).toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
  const badgeUrl = `${config.origin}/api/badge/${p.handle}.svg`;
  const snippet = `<a href="${config.origin}/u/${p.handle}"><img src="${badgeUrl}" alt="@${p.handle} on Human ID"></a>`;
  app.innerHTML = `
    <section class="card">
      <p class="big-handle">@${esc(p.handle)}</p>
      <div class="row wrap">${pill(p.freshness)}</div>
      <ul class="facts">
        <li>Human ID since ${esc(since)}</li>
        <li>Passed ${p.checksPassed} check${p.checksPassed === 1 ? '' : 's'}</li>
      </ul>
      ${KEY[p.keyType] ? `<p class="faint" data-mt>${KEY[p.keyType]}</p>` : ''}
    </section>
    ${!me ? `
      <p class="muted">Want to check that @${esc(p.handle)} is a live human right now? You need your own Human ID first. It takes a minute.</p>
      <a class="btn primary block" href="/join" data-link>Create your Human ID</a>` : ''}
    ${me && p.isMe ? `
      <section class="card">
        <h2>This is you</h2>
        <p class="muted small">Show a live badge anywhere that accepts images, like a website or GitHub profile:</p>
        <img class="badge-img" src="/api/badge/${esc(p.handle)}.svg" alt="Your live badge">
        <div class="linkbox">${esc(snippet)}</div>
        <button class="small" id="copy-snippet" data-mt>Copy badge code</button>
      </section>` : ''}
    ${me && !p.isMe ? `
      <div class="stack">
        ${p.canCheck ? '<button class="primary block" id="check">Ask them to prove it</button>' : `<div class="card"><p class="muted">${esc(p.cantCheckReason)}</p></div>`}
        <button class="block" id="contact">${p.isContact ? 'Remove from your people' : 'Add to your people'}</button>
        <button class="ghost block small" id="block">${p.isBlocked ? 'Unblock' : 'Block'} @${esc(p.handle)}</button>
      </div>` : ''}`;
  if (!me) store.set('hid-next', `/u/${p.handle}`);
  $('#copy-snippet')?.addEventListener('click', () => copy(snippet, 'Badge code copied'));
  $('#check')?.addEventListener('click', (e) => sendCheck(p.handle, e.currentTarget));
  $('#contact')?.addEventListener('click', async (e) => {
    const ok = await busy(e.currentTarget, () => (p.isContact ? api('DELETE', `/api/contacts/${p.handle}`) : api('POST', '/api/contacts', { handle: p.handle })));
    if (ok) render();
  });
  $('#block')?.addEventListener('click', async (e) => {
    if (!p.isBlocked && !confirm(`Block @${p.handle}? They won't be able to send you checks.`)) return;
    const ok = await busy(e.currentTarget, () => (p.isBlocked ? api('DELETE', `/api/blocks/${p.handle}`) : api('POST', '/api/blocks', { handle: p.handle })));
    if (ok) render();
  });
}

async function viewSettings() {
  if (!requireMe()) return;
  const [passkeys, blocks] = await Promise.all([api('GET', '/api/passkeys'), api('GET', '/api/blocks')]);
  const push = pushAvailability();
  const subscribed = push === 'ok' ? await pushSubscription().catch(() => null) : null;
  const choice = (value, title, text) => `
    <label class="choice"><input type="radio" name="policy" value="${value}" ${me.policy === value ? 'checked' : ''}>
    <span><strong>${title}</strong><br><span class="muted small">${text}</span></span></label>`;

  app.innerHTML = `
    <h1>Settings</h1>
    <section class="card">
      <h2>Who can check you</h2>
      ${choice('anyone', 'Anyone with your handle', 'Best if you give your handle to new people, like on dating apps or in business.')}
      ${choice('contacts', 'Only people you added', 'Strangers can\'t send you checks.')}
      ${choice('nobody', 'Nobody right now', 'Pause all checks.')}
    </section>

    <section class="card">
      <h2>Your passkeys</h2>
      <p class="muted small">Each device that can answer checks for you. If you lose all of them, this handle can't be recovered, so add a second device.</p>
      <ul class="list">${passkeys.map((k, i) => `
        <li><span class="grow">Passkey ${i + 1}<br>
        <span class="faint">${k.deviceType === 'singleDevice' ? 'On one device only' : 'Synced across your devices'} · added ${ago(k.createdAt)} · used ${ago(k.lastUsedAt)}</span></span>
        ${passkeys.length > 1 ? `<button class="small" data-remove="${esc(k.id)}">Remove</button>` : ''}</li>`).join('')}
      </ul>
      <button class="small" id="add-key">Add a passkey on this device</button>
    </section>

    <section class="card">
      <h2>Alerts</h2>
      ${push === 'ok' ? `<p class="muted small">${subscribed ? 'Alerts are on for this device.' : 'Alerts are off for this device.'}</p>
        <button class="small" id="push">${subscribed ? 'Turn off alerts' : 'Turn on alerts'}</button>` : ''}
      ${push === 'ios-install' ? '<p class="muted small">On iPhone, add Human ID to your Home Screen (Share, then "Add to Home Screen") to get alerts.</p>' : ''}
      ${push === 'denied' ? '<p class="muted small">Alerts are blocked in your browser settings for this site.</p>' : ''}
      ${push === 'unsupported' || push === 'server-off' ? '<p class="muted small">Alerts aren\'t available here.</p>' : ''}
    </section>

    ${blocks.length ? `
    <section class="card">
      <h2>Blocked</h2>
      <ul class="list">${blocks.map((h) => `<li><span class="grow">@${esc(h)}</span><button class="small" data-unblock="${esc(h)}">Unblock</button></li>`).join('')}</ul>
    </section>` : ''}

    <div class="stack">
      <button class="block" id="logout">Sign out</button>
      <button class="danger block" id="delete">Delete my Human ID</button>
    </div>`;

  $$('input[name=policy]').forEach((r) => r.addEventListener('change', async () => {
    const res = await busy(null, () => api('PATCH', '/api/me', { policy: r.value }));
    if (res) { me = res; toast('Saved'); }
  }));
  $('#add-key').addEventListener('click', async (e) => {
    const ok = await busy(e.currentTarget, () => withFreshFace(() => ceremony('/api/passkeys/begin', '/api/passkeys/finish', {}, 'create')));
    if (ok) { toast('Passkey added'); render(); }
  });
  $$('[data-remove]').forEach((b) => b.addEventListener('click', async () => {
    if (!confirm('Remove this passkey? That device will stop answering checks for you.')) return;
    const ok = await busy(b, () => withFreshFace(() => api('DELETE', `/api/passkeys/${encodeURIComponent(b.dataset.remove)}`)));
    if (ok) { toast('Passkey removed'); render(); }
  }));
  $('#push')?.addEventListener('click', async (e) => {
    const ok = await busy(e.currentTarget, async () => { if (subscribed) await disablePush(); else await enablePush(); return true; });
    if (ok) render();
  });
  $$('[data-unblock]').forEach((b) => b.addEventListener('click', async () => {
    if (await busy(b, () => api('DELETE', `/api/blocks/${b.dataset.unblock}`))) render();
  }));
  $('#logout').addEventListener('click', async (e) => {
    if (await busy(e.currentTarget, () => api('POST', '/api/logout'))) { me = null; navigate('/'); }
  });
  $('#delete').addEventListener('click', async (e) => {
    if (!confirm(`Delete @${me.handle} for good? Nobody, including you, can ever use this handle again.`)) return;
    const ok = await busy(e.currentTarget, () => withFreshFace(() => api('POST', '/api/me/delete')));
    if (ok) { me = null; toast('Your Human ID is deleted'); navigate('/'); }
  });
}

function viewVerify() {
  const fromHash = location.hash.slice(1);
  app.innerHTML = `
    <h1>Verify a receipt</h1>
    <p class="muted">Every passed check comes with a signed receipt. Paste one here to confirm it's real. The check runs in your browser against this site's published key.</p>
    <textarea id="token" placeholder="eyJhbGciOiJFUzI1NiIs…">${esc(fromHash)}</textarea>
    <button class="primary block" id="go" data-mt>Verify</button>
    <div id="result"></div>`;
  $('#go').addEventListener('click', async (e) => {
    const res = await busy(e.currentTarget, () => verifyReceipt($('#token').value, '/.well-known/jwks.json'));
    if (!res) return;
    const c = res.claims;
    const when = c.iat ? new Date(c.iat * 1000).toLocaleString() : 'an unknown time';
    const foreign = c.iss && c.iss !== config.origin;
    $('#result').innerHTML = res.valid && !foreign
      ? `<section class="card success"><h2>Real receipt</h2><p>@${esc(c.sub)} passed a human check from @${esc(c.aud)} on ${esc(when)}.</p>
         <p class="small">Face, fingerprint, or passcode confirmed on their phone${c.code_matched ? ', and the three words matched' : ''}.</p></section>`
      : `<section class="card warn"><h2>Not valid</h2><p>${esc(foreign ? `This receipt claims to be from ${c.iss}, not this site.` : res.reason)}</p></section>`;
  });
}

function viewHow() {
  app.innerHTML = `
    <h1>How it works</h1>
    <ol class="steps">
      <li><strong>Your handle is locked to your phone.</strong> When you sign up, your phone makes a passkey: a secret key sealed in its security chip that only opens with your face, fingerprint, or passcode. We only ever see the public half.</li>
      <li><strong>Someone sends you a check.</strong> It comes with three random words. On a call they say the words; in a chat they send a link that carries them.</li>
      <li><strong>You answer with your face.</strong> Your phone signs that exact check. We confirm the signature and the words, and they see you passed.</li>
    </ol>

    <section class="card">
      <h2>What a pass proves</h2>
      <ul class="facts">
        <li>A person unlocked the phone that owns this handle, just now.</li>
        <li>That person got the three words from whoever sent the check, so they're the one you're talking to.</li>
        <li>An AI or bot on a server can't answer on its own. It would need the phone and the person.</li>
      </ul>
    </section>

    <section class="card">
      <h2>What it can't prove</h2>
      <ul class="facts no">
        <li>Who someone is in real life. A pass means "a live human", not "your bank" or "your mom".</li>
        <li>That they wrote their messages themselves. A person can still read out an AI's script.</li>
        <li>That nobody is forcing them, or sitting next to them.</li>
        <li>Whether it was a face or a passcode. Phones don't tell websites which one was used.</li>
        <li>That one person has only one handle. This first version has no passport check.</li>
      </ul>
    </section>

    <section class="card">
      <h2>Your privacy</h2>
      <ul class="facts">
        <li>No name, email, phone number, or photo is ever collected.</li>
        <li>Your face never leaves your phone.</li>
        <li>Others see only "today", "this week", or "overdue", never exact times.</li>
        <li>You choose who can check you, and can block anyone.</li>
      </ul>
    </section>

    <details><summary>How do I trust a handle more?</summary><p class="muted">Older handles with many passed checks are harder to fake. A passkey on one device only is stronger than one that syncs across devices. Best of all: check someone once when you know it's really them, add them to your people, and check again whenever something feels off.</p></details>
    <details><summary>Can I check a receipt myself?</summary><p class="muted">Yes. Each passed check produces a signed receipt (a standard JWT). Anyone can verify it on the <a href="/verify" data-link>verify page</a> or with any JWT library, using the public key at <span class="mono">/.well-known/jwks.json</span>.</p></details>
    <details><summary>Is it open source?</summary><p class="muted">Yes. All the code is public, so anyone can check exactly what it does.</p></details>`;
}

// ---------- Start ----------

(async () => {
  config = await api('GET', '/api/config').catch(() => config);
  await refreshMe();
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
  render();
})();
