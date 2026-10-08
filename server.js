// Ledger & Lens game server: serves the game, runs live rooms (lobby + matches + chat) over WebSocket,
// and stores rankings and cloud saves. Storage: Postgres if DATABASE_URL is set, else a JSON file.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
// The game file can sit at the top level (index.html) or in public/index.html
const GAME_PATH = [path.join(__dirname, 'index.html'), path.join(__dirname, 'public', 'index.html')].find(p => fs.existsSync(p));
if (!GAME_PATH) { console.error('Game file missing: upload index.html to the top level of the repository.'); process.exit(1); }
const GAME = fs.readFileSync(GAME_PATH, 'utf8');

// ---------------- storage ----------------
const mem = { players: {}, saves: {}, ids: {} }; // ids: uid -> sha256(token)
let pg = null;
async function initStore() {
  if (process.env.DATABASE_URL) {
    const { Pool } = require('pg');
    pg = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === 'off' ? false : { rejectUnauthorized: false } });
    await pg.query('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v JSONB NOT NULL)');
    const r = await pg.query('SELECT k, v FROM kv');
    for (const row of r.rows) {
      const [kind, id] = row.k.split(':');
      if (mem[kind]) mem[kind][id] = row.v;
    }
    console.log(`Postgres store: ${Object.keys(mem.players).length} players`);
  } else {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    try { Object.assign(mem, JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'db.json'), 'utf8'))); } catch (e) {}
    console.log(`File store at ${DATA_DIR}: ${Object.keys(mem.players).length} players`);
  }
}
let fileT = null;
async function put(kind, id, v) {
  mem[kind][id] = v;
  if (pg) {
    try { await pg.query('INSERT INTO kv (k, v) VALUES ($1, $2) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v', [`${kind}:${id}`, JSON.stringify(v)]); }
    catch (e) { console.error('db write failed', e.message); }
  } else {
    clearTimeout(fileT);
    fileT = setTimeout(() => {
      const tmp = path.join(DATA_DIR, 'db.json.tmp');
      fs.writeFile(tmp, JSON.stringify(mem), err => { if (!err) fs.rename(tmp, path.join(DATA_DIR, 'db.json'), () => {}); });
    }, 1000);
  }
}

// ---------------- http ----------------
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/api/ping') {
    res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
    return res.end(JSON.stringify({ ok: true, game: 'ledger-lens', players: Object.keys(mem.players).length }));
  }
  if (url.pathname === '/' || url.pathname === '/index.html') {
    const proto = (req.headers['x-forwarded-proto'] || 'http').split(',')[0];
    const origin = `${proto}://${req.headers.host}`;
    const html = GAME.replace('<!--LL_SERVER-->', `<script>window.LL_SERVER=${JSON.stringify(origin)};</script>`);
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache' });
    return res.end(html);
  }
  if (url.pathname === '/healthz') { res.writeHead(200); return res.end('ok'); }
  res.writeHead(404, { 'content-type': 'text/plain' }); res.end('Not found');
});

// ---------------- live rooms ----------------
const wss = new WebSocketServer({ server, maxPayload: 64 * 1024 });
const rooms = new Map(); // name -> Map(connId -> {ws, by, p})
const TOPIC = /^[a-z][a-z0-9_.-]{0,47}$/;
const ROOM = /^[a-z0-9][a-z0-9_.-]{0,47}$/;
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const send = (ws, m) => { if (ws.readyState === 1) ws.send(JSON.stringify(m)); };
const sizeOk = (v, max = 4096) => { try { return JSON.stringify(v ?? null).length <= max; } catch (e) { return false; } };

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
function leaveRoom(c, name) {
  const r = rooms.get(name); if (!r) return;
  r.delete(c.id); c.rooms.delete(name);
  if (!r.size) rooms.delete(name); else broadcastPeers(name);
}
function boardList() {
  return Object.entries(mem.players).map(([id, v]) => Object.assign({ id }, v))
    .sort((a, b) => (b.xp || 0) - (a.xp || 0)).slice(0, 200);
}
let boardT = null;
function pushBoard() {
  clearTimeout(boardT);
  boardT = setTimeout(() => { const list = boardList(); for (const c of conns.values()) if (c.subBoard) send(c.ws, { t: 'board', list }); }, 300);
}

const conns = new Map();
wss.on('connection', ws => {
  const c = { id: crypto.randomBytes(8).toString('hex'), ws, uid: null, rooms: new Set(), subBoard: false, bucket: 80, last: Date.now() };
  conns.set(c.id, c);
  ws.on('message', raw => {
    // rate limit: ~40 msgs/s, burst 80
    const now = Date.now(); c.bucket = Math.min(80, c.bucket + (now - c.last) * 0.04); c.last = now;
    if (c.bucket < 1) return; c.bucket--;
    let m; try { m = JSON.parse(raw); } catch (e) { return; }
    if (!m || typeof m !== 'object') return;

    if (m.t === 'hello') {
      let uid = typeof m.uid === 'string' && /^u_[a-z0-9]{8,40}$/.test(m.uid) ? m.uid : null;
      const token = typeof m.token === 'string' ? m.token : '';
      if (!uid || !mem.ids[uid] || mem.ids[uid] !== sha(token)) {
        if (uid && !mem.ids[uid] && token.length >= 20) { put('ids', uid, sha(token)); }
        else { uid = 'u_' + crypto.randomBytes(10).toString('hex'); const tk = crypto.randomBytes(24).toString('hex'); put('ids', uid, sha(tk)); c.uid = uid; return send(ws, { t: 'welcome', uid, token: tk, peer: c.id }); }
      }
      c.uid = uid; return send(ws, { t: 'welcome', uid, token, peer: c.id });
    }
    if (!c.uid) return;
    const name = typeof m.room === 'string' ? m.room : null;

    switch (m.t) {
      case 'join': {
        if (!name || !(name === 'lobby' || ROOM.test(name))) return;
        if (c.rooms.size >= 16 && !c.rooms.has(name)) return send(ws, { t: 'joinres', id: m.id, err: 'limit_reached' });
        if (!rooms.has(name)) rooms.set(name, new Map());
        rooms.get(name).set(c.id, { ws, by: c.uid, p: {} }); c.rooms.add(name);
        send(ws, { t: 'joinres', id: m.id, room: name }); broadcastPeers(name); return;
      }
      case 'leave': if (name) leaveRoom(c, name); return;
      case 'presence': {
        const r = name && rooms.get(name); if (!r || !r.has(c.id) || !m.p || typeof m.p !== 'object' || !sizeOk(m.p)) return;
        r.get(c.id).p = m.p; broadcastPeers(name); return;
      }
      case 'emit': {
        const r = name && rooms.get(name); if (!r || !r.has(c.id) || !TOPIC.test(m.topic || '') || !sizeOk(m.data)) return;
        const ev = { t: 'event', room: name, topic: m.topic, data: m.data ?? null, from: c.id, by: c.uid };
        for (const mm of r.values()) send(mm.ws, ev); return;
      }
      case 'board.sub': c.subBoard = true; send(ws, { t: 'board', list: boardList() }); return;
      case 'save.get': return send(ws, { t: 'res', id: m.id, data: mem.saves[c.uid] || null });
      case 'save.set': if (sizeOk(m.data, 200 * 1024)) put('saves', c.uid, m.data); return send(ws, { t: 'res', id: m.id, ok: true });
      case 'player.set': {
        const d = m.data; if (!d || typeof d !== 'object' || !sizeOk(d, 2048)) return;
        const num = v => (Number.isFinite(+v) ? Math.max(0, Math.min(1e7, Math.round(+v))) : 0);
        const clean = { nick: String(d.nick || 'Investigator').replace(/[\u0000-\u001f]/g, '').slice(0, 28), rank: String(d.rank || '').slice(0, 40),
          xp: num(d.xp), cases: Math.min(23, num(d.cases)), stars: Math.min(69, num(d.stars)), streak: num(d.streak), bestStreak: num(d.bestStreak),
          wins: num(d.wins), played: num(d.played), best: num(d.best), partner: !!d.partner, updatedAt: Date.now() };
        put('players', c.uid, clean); pushBoard(); return send(ws, { t: 'res', id: m.id, ok: true });
      }
    }
  });
  ws.on('close', () => { for (const n of [...c.rooms]) leaveRoom(c, n); conns.delete(c.id); });
  ws.on('error', () => {});
});
// keepalive so hosting proxies don't drop idle sockets
setInterval(() => { for (const c of conns.values()) if (c.ws.readyState === 1) c.ws.ping(); }, 25000);

initStore().then(() => server.listen(PORT, () => console.log(`Ledger & Lens server on :${PORT}`)));
