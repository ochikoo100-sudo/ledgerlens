// Ledger & Lens game server: serves the game, user accounts (username + password), live rooms
// (lobby, matches, chat) over WebSocket, rankings and cloud saves.
// Storage: Postgres if DATABASE_URL is set, else a JSON file.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const GAME_PATH = [path.join(__dirname, 'index.html'), path.join(__dirname, 'public', 'index.html')].find(p => fs.existsSync(p));
if (!GAME_PATH) { console.error('Game file missing: upload index.html to the top level of the repository.'); process.exit(1); }
const GAME = fs.readFileSync(GAME_PATH, 'utf8');
const SESSION_DAYS = 30;
const COOKIE = 'll_sess';

// ---------------- storage ----------------
// ids: guest uid -> sha256(token) · accounts: lower(username) -> account · sessions: sha256(token) -> session
const mem = { players: {}, saves: {}, ids: {}, accounts: {}, sessions: {}, cheat: {} };
let pg = null;
async function initStore() {
  if (process.env.DATABASE_URL) {
    const { Pool } = require('pg');
    pg = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === 'off' ? false : { rejectUnauthorized: false } });
    await pg.query('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v JSONB NOT NULL)');
    const r = await pg.query('SELECT k, v FROM kv');
    for (const row of r.rows) {
      const i = row.k.indexOf(':'); const kind = row.k.slice(0, i), id = row.k.slice(i + 1);
      if (mem[kind]) mem[kind][id] = row.v;
    }
    console.log(`Postgres store: ${Object.keys(mem.accounts).length} accounts, ${Object.keys(mem.players).length} players`);
  } else {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    try { const d = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'db.json'), 'utf8')); for (const k of Object.keys(mem)) if (d[k]) mem[k] = d[k]; } catch (e) {}
    console.log(`File store at ${DATA_DIR}: ${Object.keys(mem.accounts).length} accounts (set DATABASE_URL for permanent storage)`);
  }
  // drop expired sessions
  const now = Date.now(); for (const [k, s] of Object.entries(mem.sessions)) if (s.exp < now) del('sessions', k);
}
let fileT = null;
function flushFile() {
  clearTimeout(fileT);
  fileT = setTimeout(() => { const tmp = path.join(DATA_DIR, 'db.json.tmp'); fs.writeFile(tmp, JSON.stringify(mem), err => { if (!err) fs.rename(tmp, path.join(DATA_DIR, 'db.json'), () => {}); }); }, 1000);
}
async function put(kind, id, v) {
  mem[kind][id] = v;
  if (pg) { try { await pg.query('INSERT INTO kv (k, v) VALUES ($1, $2) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v', [`${kind}:${id}`, JSON.stringify(v)]); } catch (e) { console.error('db write failed', e.message); } }
  else flushFile();
}
async function del(kind, id) {
  delete mem[kind][id];
  if (pg) { try { await pg.query('DELETE FROM kv WHERE k = $1', [`${kind}:${id}`]); } catch (e) { console.error('db delete failed', e.message); } }
  else flushFile();
}

// ---------------- helpers ----------------
const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const rand = (n = 32) => crypto.randomBytes(n).toString('hex');
const sizeOk = (v, max = 4096) => { try { return JSON.stringify(v ?? null).length <= max; } catch (e) { return false; } };
const accountByUid = uid => { for (const a of Object.values(mem.accounts)) if (a.uid === uid) return a; return null; };
const clientIp = req => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

// passwords: scrypt (memory-hard, built into Node), random salt, constant-time compare
const SCRYPT = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
function hashPassword(pw) {
  return new Promise((res, rej) => { const salt = crypto.randomBytes(16);
    crypto.scrypt(pw, salt, 64, SCRYPT, (e, key) => e ? rej(e) : res(`scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`)); });
}
function verifyPassword(pw, stored) {
  return new Promise(res => {
    const parts = String(stored || '').split('$');
    const ok = parts.length === 6 && parts[0] === 'scrypt';
    const salt = ok ? Buffer.from(parts[4], 'base64') : crypto.randomBytes(16), want = ok ? Buffer.from(parts[5], 'base64') : crypto.randomBytes(64);
    const opt = ok ? { N: +parts[1], r: +parts[2], p: +parts[3], maxmem: 64 * 1024 * 1024 } : SCRYPT;
    crypto.scrypt(pw, salt, want.length, opt, (e, key) => res(!e && ok && crypto.timingSafeEqual(key, want)));
  });
}
const DUMMY_HASH = 'scrypt$32768$8$1$AAAAAAAAAAAAAAAAAAAAAA==$' + Buffer.alloc(64).toString('base64');
const COMMON = new Set(('password,password1,password123,12345678,123456789,1234567890,qwerty123,qwertyuiop,iloveyou,11111111,00000000,abc12345,abcd1234,' +
  'letmein1,welcome1,admin123,football,baseball,sunshine,princess,dragon12,monkey12,passw0rd,trustno1,superman,starwars,whatever,12341234,' +
  'asdfghjk,zxcvbnm1,1q2w3e4r,1qaz2wsx,q1w2e3r4,qwerty12,87654321,11223344,aaaaaaaa,accounting,acca1234,ledgerlens').split(','));
async function breached(pw) { // Have I Been Pwned k-anonymity: only the first 5 hex chars of the SHA-1 leave the server
  try {
    const h = crypto.createHash('sha1').update(pw).digest('hex').toUpperCase();
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 2500);
    const r = await fetch('https://api.pwnedpasswords.com/range/' + h.slice(0, 5), { signal: ctl.signal, headers: { 'Add-Padding': 'true' } }); clearTimeout(t);
    if (!r.ok) return false; const body = await r.text();
    return body.split('\n').some(l => { const [suf, n] = l.trim().split(':'); return suf === h.slice(5) && +n > 0; });
  } catch (e) { return false; }
}
async function passwordProblem(pw, username) {
  if (typeof pw !== 'string' || pw.length < 8) return 'Use at least 8 characters.';
  if (pw.length > 128) return 'That password is too long (128 characters max).';
  const low = pw.toLowerCase();
  if (COMMON.has(low) || /^(.)\1+$/.test(pw)) return 'That password is too common. Pick something harder to guess.';
  if (username && low.includes(username.toLowerCase())) return 'Don’t include your username in your password.';
  if (await breached(pw)) return 'That password has appeared in a known data breach. Please choose a different one.';
  return null;
}
const USER_RE = /^[A-Za-z0-9_]{3,20}$/;
const RESERVED = new Set(['admin', 'administrator', 'root', 'system', 'support', 'moderator', 'mod', 'staff', 'owner', 'ledgerlens', 'null', 'undefined', 'guest']);
function makeCodes() { const a = 'abcdefghjkmnpqrstuvwxyz23456789'; return Array.from({ length: 8 }, () => { let s = ''; const b = crypto.randomBytes(10); for (let i = 0; i < 10; i++) s += a[b[i] % a.length]; return s.slice(0, 5) + '-' + s.slice(5); }); }

// ---------------- rate limits (in memory) ----------------
const buckets = new Map(); // key -> {n, reset}
function limited(key, max, windowMs) {
  const now = Date.now(); let b = buckets.get(key);
  if (!b || b.reset < now) { b = { n: 0, reset: now + windowMs }; buckets.set(key, b); }
  b.n++; return b.n > max;
}
const fails = new Map(); // key -> {n, until}
function lockedFor(key) { const f = fails.get(key); return f && f.until > Date.now() ? Math.ceil((f.until - Date.now()) / 60000) : 0; }
function noteFail(key, after = 5) { const f = fails.get(key) || { n: 0, until: 0 }; f.n++; if (f.n >= after) { f.until = Date.now() + Math.min(60, 15 * 2 ** (f.n - after)) * 60000; } fails.set(key, f); }
setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) if (b.reset < now) buckets.delete(k); for (const [k, f] of fails) if (f.until < now - 3600000) fails.delete(k); }, 600000);

// ---------------- sessions ----------------
function parseCookies(h) { const o = {}; String(h || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); }); return o; }
function sessionOf(req) {
  const tok = parseCookies(req.headers.cookie)[COOKIE]; if (!tok || tok.length > 100) return null;
  const k = sha(tok), s = mem.sessions[k]; if (!s) return null;
  if (s.exp < Date.now()) { del('sessions', k); return null; }
  const acct = Object.values(mem.accounts).find(a => a.uid === s.uid); if (!acct || (acct.epoch || 0) !== (s.epoch || 0)) { del('sessions', k); return null; }
  return { key: k, s, acct };
}
const isHttps = req => (req.headers['x-forwarded-proto'] || '').split(',')[0] === 'https' || !!req.socket.encrypted;
function setSessionCookie(req, res, tok, maxAge) {
  res.setHeader('Set-Cookie', `${COOKIE}=${tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${isHttps(req) ? '; Secure' : ''}`);
}
async function newSession(req, res, acct) {
  const tok = rand(32);
  await put('sessions', sha(tok), { uid: acct.uid, exp: Date.now() + SESSION_DAYS * 864e5, at: Date.now(), epoch: acct.epoch || 0, ua: String(req.headers['user-agent'] || '').slice(0, 120) });
  setSessionCookie(req, res, tok, SESSION_DAYS * 86400);
}
async function killSessions(uid, exceptKey) { for (const [k, s] of Object.entries(mem.sessions)) if (s.uid === uid && k !== exceptKey) await del('sessions', k); for (const c of conns.values()) if (c.uid === uid && c.sessKey !== exceptKey) c.ws.close(4001, 'logged out'); }

// ---------------- http ----------------
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; connect-src 'self' ws: wss: https://0.peerjs.com wss://0.peerjs.com; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";
function secHeaders(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (isHttps(req)) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}
const json = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }); res.end(JSON.stringify(obj)); };
function readBody(req) {
  return new Promise(resolve => { let size = 0, chunks = [];
    req.on('data', c => { size += c.length; if (size > 8192) { req.destroy(); resolve(null); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch (e) { resolve(null); } });
    req.on('error', () => resolve(null)); });
}
function sameOrigin(req) { // blocks cross-site requests (CSRF): the browser always sends Origin on POST
  const o = req.headers.origin; if (!o) return false;
  try { return new URL(o).host === req.headers.host; } catch (e) { return false; }
}
const GENERIC = 'Wrong username or password.';

async function api(req, res, route) {
  const ip = clientIp(req);
  if (limited('api:' + ip, 60, 60000)) return json(res, 429, { error: 'Too many requests. Wait a minute and try again.' });
  if (route === 'me' && req.method === 'GET') { const s = sessionOf(req); return json(res, 200, s ? { user: s.acct.name, uid: s.acct.uid, created: s.acct.created } : { user: null }); }
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
  if (!sameOrigin(req)) return json(res, 403, { error: 'Blocked: request did not come from the game page.' });
  if (!/^application\/json/.test(req.headers['content-type'] || '')) return json(res, 415, { error: 'Expected JSON' });
  const b = await readBody(req); if (!b || typeof b !== 'object') return json(res, 400, { error: 'Bad request' });
  const sess = sessionOf(req);

  if (route === 'signup') {
    if (limited('signup:' + ip, 5, 3600000)) return json(res, 429, { error: 'Too many new accounts from this network. Try again later.' });
    const name = String(b.username || '').trim(), low = name.toLowerCase();
    if (!USER_RE.test(name)) return json(res, 400, { error: 'Usernames are 3–20 letters, numbers or underscores.' });
    if (RESERVED.has(low) || mem.accounts[low]) return json(res, 409, { error: 'That username is taken.' });
    const prob = await passwordProblem(b.password, name); if (prob) return json(res, 400, { error: prob });
    // keep the guest's progress if they prove they own the guest id
    let uid = null;
    if (typeof b.guestUid === 'string' && /^u_[a-z0-9]{8,40}$/.test(b.guestUid) && typeof b.guestToken === 'string' && mem.ids[b.guestUid] === sha(b.guestToken) && !accountByUid(b.guestUid)) uid = b.guestUid;
    if (!uid) uid = 'u_' + rand(10);
    const codes = makeCodes();
    if (mem.accounts[low]) return json(res, 409, { error: 'That username is taken.' });
    const acct = { name, uid, hash: await hashPassword(b.password), codes: codes.map(c => sha(c.replace('-', ''))), created: Date.now(), epoch: 0 };
    await put('accounts', low, acct); if (mem.ids[uid]) await del('ids', uid);
    await newSession(req, res, acct);
    return json(res, 200, { ok: true, user: name, codes, kept: uid === b.guestUid });
  }
  if (route === 'login') {
    const name = String(b.username || '').trim().slice(0, 40), low = name.toLowerCase();
    const wait = Math.max(lockedFor('ip:' + ip), lockedFor('user:' + low));
    if (wait) return json(res, 429, { error: `Too many failed attempts. Try again in ${wait} minute${wait > 1 ? 's' : ''}.` });
    const acct = mem.accounts[low];
    const ok = await verifyPassword(String(b.password || '').slice(0, 128), acct ? acct.hash : DUMMY_HASH); // same work whether or not the user exists
    if (!acct || !ok) { noteFail('ip:' + ip, 20); noteFail('user:' + low, 5); return json(res, 401, { error: GENERIC }); }
    fails.delete('user:' + low);
    await newSession(req, res, acct);
    return json(res, 200, { ok: true, user: acct.name });
  }
  if (route === 'recover') {
    const low = String(b.username || '').trim().toLowerCase().slice(0, 40);
    const wait = Math.max(lockedFor('ip:' + ip), lockedFor('rec:' + low)); if (wait) return json(res, 429, { error: `Too many attempts. Try again in ${wait} minutes.` });
    const acct = mem.accounts[low], code = sha(String(b.code || '').toLowerCase().replace(/[^a-z0-9]/g, ''));
    const i = acct ? acct.codes.indexOf(code) : -1;
    if (i < 0) { noteFail('ip:' + ip, 20); noteFail('rec:' + low, 5); return json(res, 401, { error: 'That username and recovery code don’t match.' }); }
    const prob = await passwordProblem(b.password, acct.name); if (prob) return json(res, 400, { error: prob });
    acct.codes.splice(i, 1); acct.hash = await hashPassword(b.password); acct.epoch = (acct.epoch || 0) + 1;
    await put('accounts', low, acct); await killSessions(acct.uid); await newSession(req, res, acct);
    return json(res, 200, { ok: true, user: acct.name, codesLeft: acct.codes.length });
  }
  // everything below needs a logged-in session
  if (!sess) return json(res, 401, { error: 'Please log in first.' });
  const acct = sess.acct, low = acct.name.toLowerCase();
  const needPassword = async () => {
    if (lockedFor('pw:' + acct.uid)) return 'Too many wrong passwords. Try again later.';
    if (!(await verifyPassword(String(b.password || '').slice(0, 128), acct.hash))) { noteFail('pw:' + acct.uid, 5); return 'Your current password is wrong.'; }
    return null;
  };
  if (route === 'logout') { await del('sessions', sess.key); setSessionCookie(req, res, '', 0); return json(res, 200, { ok: true }); }
  if (route === 'logout-all') { acct.epoch = (acct.epoch || 0) + 1; await put('accounts', low, acct); await killSessions(acct.uid); setSessionCookie(req, res, '', 0); return json(res, 200, { ok: true }); }
  if (route === 'password') {
    const e = await needPassword(); if (e) return json(res, 401, { error: e });
    const prob = await passwordProblem(b.newPassword, acct.name); if (prob) return json(res, 400, { error: prob });
    acct.hash = await hashPassword(b.newPassword); acct.epoch = (acct.epoch || 0) + 1; await put('accounts', low, acct);
    await killSessions(acct.uid); await newSession(req, res, acct); // other devices are logged out
    return json(res, 200, { ok: true });
  }
  if (route === 'codes') {
    const e = await needPassword(); if (e) return json(res, 401, { error: e });
    const codes = makeCodes(); acct.codes = codes.map(c => sha(c.replace('-', ''))); await put('accounts', low, acct);
    return json(res, 200, { ok: true, codes });
  }
  if (route === 'export') {
    const e = await needPassword(); if (e) return json(res, 401, { error: e });
    return json(res, 200, { account: { username: acct.name, created: new Date(acct.created).toISOString(), recoveryCodesLeft: acct.codes.length }, ranking: mem.players[acct.uid] || null, save: mem.saves[acct.uid] || null });
  }
  if (route === 'delete') {
    const e = await needPassword(); if (e) return json(res, 401, { error: e });
    if (String(b.confirm || '') !== acct.name) return json(res, 400, { error: 'Type your username exactly to confirm.' });
    await killSessions(acct.uid); await del('accounts', low); await del('saves', acct.uid); await del('players', acct.uid); await del('cheat', acct.uid);
    setSessionCookie(req, res, '', 0); pushBoard();
    return json(res, 200, { ok: true });
  }
  return json(res, 404, { error: 'Not found' });
}

const server = http.createServer(async (req, res) => {
  secHeaders(req, res);
  const url = new URL(req.url, 'http://x');
  try {
    if (url.pathname === '/api/ping') {
      res.setHeader('access-control-allow-origin', '*');
      return json(res, 200, { ok: true, game: 'ledger-lens', accounts: true });
    }
    if (url.pathname.startsWith('/api/auth/')) return await api(req, res, url.pathname.slice(10));
    if (url.pathname === '/' || url.pathname === '/index.html') {
      const proto = isHttps(req) ? 'https' : 'http';
      const origin = `${proto}://${req.headers.host}`;
      const html = GAME.replace('<!--LL_SERVER-->', `<script>window.LL_SERVER=${JSON.stringify(origin)};</script>`);
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache', 'Content-Security-Policy': CSP });
      return res.end(html);
    }
    if (url.pathname === '/healthz') { res.writeHead(200); return res.end('ok'); }
    res.writeHead(404, { 'content-type': 'text/plain' }); res.end('Not found');
  } catch (e) { console.error('request failed', e); if (!res.headersSent) json(res, 500, { error: 'Server error' }); }
});

// ---------------- anti-cheat for ranking updates ----------------
// Budgets refill over time; a single update can't jump further than a real player could have earned.
function refill(st, key, rate, cap, now) { const b = st[key] ?? cap; st[key] = Math.min(cap, b + (now - (st.t || now)) / 1000 * rate); }
function checkPlayer(uid, d, prev) {
  const now = Date.now(), st = mem.cheat[uid] || { strikes: [] };
  refill(st, 'xp', 4, 4000, now); refill(st, 'cs', 1 / 90, 3, now); refill(st, 'w', 1 / 40, 2, now); refill(st, 'mk', 1 / 1200, 1, now); st.t = now;
  let strike = false;
  const take = (key, want) => { if (want <= 0) return want; if (want <= st[key]) { st[key] -= want; return want; } strike = true; const got = Math.floor(st[key]); st[key] -= got; return got; };
  if (prev) {
    d.xp = (prev.xp || 0) + take('xp', d.xp - (prev.xp || 0));
    for (const k of ['fr', 'pm', 'lw']) {
      const a = prev.sub?.[k] || { c: 0, s: 0, m: 0 }, b = d.sub[k];
      b.c = a.c + take('cs', b.c - a.c); b.s = Math.min(b.s, a.s + Math.max(0, b.c - a.c) * 3 + (b.s > a.s && b.c === a.c ? 2 : 0));
      if (b.m > (a.m || 0)) { if (take('mk', 1) < 1) { b.m = a.m || 0; } }
      // the daily-challenge score can only be submitted once per day
      if (prev.dly?.d === d.dly.d && prev.dly[k] !== undefined) d.dly[k] = prev.dly[k];
      if (d.dly[k] !== undefined && d.dly[k] % 1000 > 989) { d.dly[k] = Math.floor(d.dly[k] / 1000) * 1000 + 989; strike = true; } // under 10 s for 5 questions
    }
    const dw = d.wins - (prev.wins || 0); d.wins = (prev.wins || 0) + take('w', dw);
    d.played = Math.max(d.played, d.wins);
  } else {
    // first ranking entry: allow carrying over existing guest progress, within reason
    d.xp = Math.min(d.xp, 60000); d.wins = Math.min(d.wins, 200);
  }
  d.cases = ['fr', 'pm', 'lw'].reduce((a, k) => a + d.sub[k].c, 0); d.stars = ['fr', 'pm', 'lw'].reduce((a, k) => a + d.sub[k].s, 0);
  st.strikes = st.strikes.filter(t => t > now - 864e5); if (strike) st.strikes.push(now);
  d.flagged = st.strikes.length >= 5; // hidden from public rankings for a day
  mem.cheat[uid] = st; put('cheat', uid, st);
  return d;
}

// ---------------- live rooms ----------------
const wss = new WebSocketServer({ server, maxPayload: 64 * 1024 });
const rooms = new Map();
const TOPIC = /^[a-z][a-z0-9_.-]{0,47}$/;
const ROOM = /^[a-z0-9][a-z0-9_.-]{0,47}$/;
const send = (ws, m) => { if (ws.readyState === 1) ws.send(JSON.stringify(m)); };
const peerTimers = new Map();
function broadcastPeers(name) {
  if (peerTimers.has(name)) return;
  peerTimers.set(name, setTimeout(() => {
    peerTimers.delete(name);
    const r = rooms.get(name); if (!r) return;
    const list = [...r.entries()].map(([peer, m]) => ({ peer, by: m.by, p: m.p || {} }));
    for (const m of r.values()) send(m.ws, { t: 'peers', room: name, list });
  }, 50));
}
function leaveRoom(c, name) { const r = rooms.get(name); if (!r) return; r.delete(c.id); c.rooms.delete(name); if (!r.size) rooms.delete(name); else broadcastPeers(name); }
function boardList() {
  const acctUids = new Set(Object.values(mem.accounts).map(a => a.uid));
  return Object.entries(mem.players).filter(([id, v]) => acctUids.has(id) && !v.flagged).map(([id, v]) => Object.assign({ id }, v))
    .sort((a, b) => (b.xp || 0) - (a.xp || 0)).slice(0, 200);
}
let boardT = null;
function pushBoard() { clearTimeout(boardT); boardT = setTimeout(() => { const list = boardList(); for (const c of conns.values()) if (c.subBoard) send(c.ws, { t: 'board', list }); }, 300); }

const conns = new Map(), ipConns = new Map();
wss.on('connection', (ws, req) => {
  const ip = clientIp(req), n = (ipConns.get(ip) || 0) + 1;
  if (n > 12) { ws.close(1013, 'too many connections'); return; }
  ipConns.set(ip, n);
  // only trust the login cookie when the socket comes from the game page itself (blocks cross-site WebSocket hijacking)
  let same = false; try { same = !!req.headers.origin && new URL(req.headers.origin).host === req.headers.host; } catch (e) {}
  const sess = same ? sessionOf(req) : null;
  const c = { id: rand(8), ws, uid: null, acct: sess ? sess.acct : null, sessKey: sess ? sess.key : null, rooms: new Set(), subBoard: false, bucket: 80, last: Date.now(), chatAt: 0, strikes: 0 };
  conns.set(c.id, c);
  ws.on('message', async raw => {
    const now = Date.now(); c.bucket = Math.min(80, c.bucket + (now - c.last) * 0.04); c.last = now;
    if (c.bucket < 1) { if (++c.strikes > 200) ws.close(1008, 'flood'); return; } c.bucket--;
    let m; try { m = JSON.parse(raw); } catch (e) { return; }
    if (!m || typeof m !== 'object') return;

    if (m.t === 'hello') {
      if (c.acct) { c.uid = c.acct.uid; return send(ws, { t: 'welcome', uid: c.uid, token: '', peer: c.id, acct: c.acct.name }); }
      let uid = typeof m.uid === 'string' && /^u_[a-z0-9]{8,40}$/.test(m.uid) ? m.uid : null;
      const token = typeof m.token === 'string' ? m.token.slice(0, 100) : '';
      if (uid && accountByUid(uid)) uid = null; // a guest id that became an account needs the password now
      if (!uid || !mem.ids[uid] || mem.ids[uid] !== sha(token)) {
        if (uid && !mem.ids[uid] && token.length >= 20 && !mem.players[uid] && !mem.saves[uid]) { put('ids', uid, sha(token)); }
        else { uid = 'u_' + rand(10); const tk = rand(24); put('ids', uid, sha(tk)); c.uid = uid; return send(ws, { t: 'welcome', uid, token: tk, peer: c.id, acct: null }); }
      }
      c.uid = uid; return send(ws, { t: 'welcome', uid, token, peer: c.id, acct: null });
    }
    if (!c.uid) return;
    const name = typeof m.room === 'string' ? m.room : null;
    switch (m.t) {
      case 'join': {
        if (!name || !(name === 'lobby' || ROOM.test(name))) return;
        if (c.rooms.size >= 16 && !c.rooms.has(name)) return send(ws, { t: 'joinres', id: m.id, err: 'limit_reached' });
        if (!rooms.has(name)) rooms.set(name, new Map());
        if (rooms.get(name).size >= 60 && !rooms.get(name).has(c.id)) return send(ws, { t: 'joinres', id: m.id, err: 'limit_reached' });
        rooms.get(name).set(c.id, { ws, by: c.uid, p: {} }); c.rooms.add(name);
        send(ws, { t: 'joinres', id: m.id, room: name }); broadcastPeers(name); return;
      }
      case 'leave': if (name) leaveRoom(c, name); return;
      case 'presence': {
        const r = name && rooms.get(name); if (!r || !r.has(c.id) || !m.p || typeof m.p !== 'object' || !sizeOk(m.p)) return;
        if (c.acct && m.p.nick !== undefined) m.p.nick = String(m.p.nick).slice(0, 28);
        r.get(c.id).p = m.p; broadcastPeers(name); return;
      }
      case 'emit': {
        const r = name && rooms.get(name); if (!r || !r.has(c.id) || !TOPIC.test(m.topic || '') || !sizeOk(m.data, 2048)) return;
        if (m.topic === 'chat') {
          if (!c.acct) return send(ws, { t: 'notice', code: 'login_to_chat' });
          if (now - c.chatAt < 700) return; c.chatAt = now;
          const t = String((m.data || {}).t || '').replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, '').trim().slice(0, 200); if (!t) return; m.data = { t };
        }
        const ev = { t: 'event', room: name, topic: m.topic, data: m.data ?? null, from: c.id, by: c.uid };
        for (const mm of r.values()) send(mm.ws, ev); return;
      }
      case 'board.sub': c.subBoard = true; send(ws, { t: 'board', list: boardList() }); return;
      case 'save.get': return send(ws, { t: 'res', id: m.id, data: mem.saves[c.uid] || null });
      case 'save.set': if (sizeOk(m.data, 300 * 1024)) put('saves', c.uid, m.data); return send(ws, { t: 'res', id: m.id, ok: true });
      case 'player.set': {
        if (!c.acct) return send(ws, { t: 'res', id: m.id, ok: false, err: 'guest' }); // rankings are for accounts
        const d = m.data; if (!d || typeof d !== 'object' || !sizeOk(d, 4096)) return;
        const num = v => (Number.isFinite(+v) ? Math.max(0, Math.min(1e7, Math.round(+v))) : 0);
        const clean = { nick: String(d.nick || c.acct.name).replace(/[\u0000-\u001f\u007f​-‏‪-‮]/g, '').trim().slice(0, 28) || c.acct.name, user: c.acct.name,
          rank: String(d.rank || '').slice(0, 40), xp: num(d.xp), streak: Math.min(3650, num(d.streak)), bestStreak: Math.min(3650, num(d.bestStreak)),
          wins: num(d.wins), played: num(d.played), best: Math.min(5000, num(d.best)), partner: !!d.partner, updatedAt: Date.now(), av: Math.min(11, num(d.av)), avc: Math.min(7, num(d.avc)),
          subj: ['fr', 'pm', 'lw'].includes(d.subj) ? d.subj : 'fr',
          group: /^[a-z0-9]{6}$/.test(d.group || '') ? d.group : '', gname: String(d.gname || '').replace(/[\u0000-\u001f]/g, '').slice(0, 30),
          sub: {}, dly: { d: /^\d{4}-\d{2}-\d{2}$/.test((d.dly || {}).d || '') ? d.dly.d : '' } };
        const lim = { fr: 23, pm: 21, lw: 19 };
        for (const k of ['fr', 'pm', 'lw']) {
          const x = (d.sub && d.sub[k]) || {};
          clean.sub[k] = { c: Math.min(lim[k], num(x.c)), s: Math.min(lim[k] * 3, num(x.s)), m: Math.min(100, num(x.m)), f: x.f ? 1 : 0 };
          if (d.dly && d.dly[k] !== undefined) clean.dly[k] = Math.min(5999, num(d.dly[k]));
        }
        put('players', c.uid, checkPlayer(c.uid, clean, mem.players[c.uid])); pushBoard(); return send(ws, { t: 'res', id: m.id, ok: true });
      }
    }
  });
  ws.on('close', () => { for (const n of [...c.rooms]) leaveRoom(c, n); conns.delete(c.id); const k = (ipConns.get(ip) || 1) - 1; if (k) ipConns.set(ip, k); else ipConns.delete(ip); });
  ws.on('error', () => {});
});
setInterval(() => { for (const c of conns.values()) if (c.ws.readyState === 1) c.ws.ping(); }, 25000);
setInterval(() => { const now = Date.now(); for (const [k, s] of Object.entries(mem.sessions)) if (s.exp < now) del('sessions', k); }, 3600000);

initStore().then(() => server.listen(PORT, () => console.log(`Ledger & Lens server on :${PORT}`)));
