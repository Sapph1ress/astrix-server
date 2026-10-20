/**
 * Astrix realtime messenger backend (simple, single-file)
 * Run: npm install && npm start
 * Default port: 3847
 */
const express = require('express');
const cors = require('cors');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3847;
const DATA = path.join(__dirname, 'data.json');

function load() {
  try {
    return JSON.parse(fs.readFileSync(DATA, 'utf8'));
  } catch {
    return { users: {}, messages: {} };
  }
}
function save(db) {
  fs.writeFileSync(DATA, JSON.stringify(db, null, 0));
}

let db = load();
const sessions = new Map(); // token -> login
const sockets = new Map(); // login -> Set<ws>

function threadKey(a, b) {
  return [a, b].sort().join('|');
}
function tokenFor(login) {
  const t = crypto.randomBytes(24).toString('hex');
  sessions.set(t, login);
  return t;
}
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : (req.query.token || '');
  const login = sessions.get(t);
  if (!login || !db.users[login]) return res.status(401).json({ error: 'unauthorized' });
  req.login = login;
  req.token = t;
  next();
}
function publicUser(login) {
  const u = db.users[login];
  if (!u) return null;
  return {
    login,
    name: u.name || login,
    bio: u.bio || '',
    color: u.color || '#3d8bfd',
    photo: u.photo || null,
    banner: u.banner || null,
    bannerType: u.bannerType || null,
    hasTrack: !!(u.trackMeta && u.trackMeta.id),
  };
}
function push(login, payload) {
  const set = sockets.get(login);
  if (!set) return;
  const raw = JSON.stringify(payload);
  for (const ws of set) {
    try { if (ws.readyState === 1) ws.send(raw); } catch {}
  }
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '12mb' }));

app.get('/', (_, res) => {
  res.type('text').send('Astrix server OK. Use the app: set this URL in settings.');
});
app.get('/api/health', (_, res) => res.json({ ok: true, users: Object.keys(db.users).length }));

app.post('/api/register', (req, res) => {
  let { login, password, name } = req.body || {};
  login = String(login || '').trim().toLowerCase().replace(/[^a-z0-9_а-яё]/gi, '');
  password = String(password || '');
  name = String(name || login).slice(0, 24);
  if (login.length < 3 || password.length < 1) return res.status(400).json({ error: 'bad_request' });
  if (db.users[login]) return res.status(409).json({ error: 'taken' });
  db.users[login] = {
    password,
    name,
    bio: '',
    color: '#3d8bfd',
    photo: null,
    banner: null,
    bannerType: null,
    trackMeta: null,
  };
  save(db);
  const token = tokenFor(login);
  res.json({ token, user: publicUser(login) });
});

app.post('/api/login', (req, res) => {
  let { login, password } = req.body || {};
  login = String(login || '').trim().toLowerCase();
  password = String(password || '');
  const u = db.users[login];
  if (!u || String(u.password) !== password) return res.status(401).json({ error: 'invalid' });
  const token = tokenFor(login);
  res.json({ token, user: publicUser(login) });
});

app.get('/api/users', auth, (req, res) => {
  const list = Object.keys(db.users)
    .filter((l) => l !== req.login)
    .map(publicUser);
  res.json({ users: list });
});

app.get('/api/profile/:login', auth, (req, res) => {
  const u = publicUser(req.params.login);
  if (!u) return res.status(404).json({ error: 'not_found' });
  res.json({ user: u });
});

app.patch('/api/me', auth, (req, res) => {
  const u = db.users[req.login];
  if (!u) return res.status(404).json({ error: 'not_found' });
  const { name, bio, color, photo, banner, bannerType } = req.body || {};
  if (name != null) u.name = String(name).slice(0, 24);
  if (bio != null) u.bio = String(bio).slice(0, 160);
  if (color != null) u.color = String(color);
  if (photo !== undefined) u.photo = photo;
  if (banner !== undefined) u.banner = banner;
  if (bannerType !== undefined) u.bannerType = bannerType;
  save(db);
  res.json({ user: publicUser(req.login) });
});

app.get('/api/chats', auth, (req, res) => {
  const me = req.login;
  const chats = [];
  for (const key of Object.keys(db.messages)) {
    const parts = key.split('|');
    if (!parts.includes(me)) continue;
    const other = parts[0] === me ? parts[1] : parts[0];
    const list = db.messages[key] || [];
    const last = list[list.length - 1];
    chats.push({
      with: other,
      user: publicUser(other),
      last: last || null,
    });
  }
  chats.sort((a, b) => (b.last?.ts || 0) - (a.last?.ts || 0));
  res.json({ chats });
});

app.get('/api/messages/:with', auth, (req, res) => {
  const other = String(req.params.with).toLowerCase();
  const key = threadKey(req.login, other);
  res.json({ messages: db.messages[key] || [] });
});

app.post('/api/messages', auth, (req, res) => {
  const to = String(req.body?.to || '').toLowerCase();
  const text = String(req.body?.text || '').slice(0, 4000);
  const img = req.body?.img || null;
  if (!db.users[to]) return res.status(404).json({ error: 'not_found' });
  if (!text && !img) return res.status(400).json({ error: 'empty' });
  const key = threadKey(req.login, to);
  if (!db.messages[key]) db.messages[key] = [];
  const msg = {
    id: crypto.randomBytes(8).toString('hex'),
    from: req.login,
    to,
    text,
    img,
    ts: Date.now(),
  };
  db.messages[key].push(msg);
  if (db.messages[key].length > 500) db.messages[key] = db.messages[key].slice(-500);
  save(db);
  push(to, { type: 'message', message: msg });
  push(req.login, { type: 'message', message: msg });
  res.json({ message: msg });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws, req) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    const token = url.searchParams.get('token') || '';
    const login = sessions.get(token);
    if (!login) {
      ws.close();
      return;
    }
    ws.login = login;
    if (!sockets.has(login)) sockets.set(login, new Set());
    sockets.get(login).add(ws);
    ws.send(JSON.stringify({ type: 'hello', login }));
    ws.on('close', () => {
      const set = sockets.get(login);
      if (set) {
        set.delete(ws);
        if (!set.size) sockets.delete(login);
      }
    });
  } catch {
    ws.close();
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('Astrix server on http://0.0.0.0:' + PORT);
});
