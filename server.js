/**
 * Astrix server v2 — users, DMs, groups
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
    const d = JSON.parse(fs.readFileSync(DATA, 'utf8'));
    if (!d.users) d.users = {};
    if (!d.messages) d.messages = {};
    if (!d.groups) d.groups = {};
    if (!d.sessions) d.sessions = {};
    return d;
  } catch {
    return { users: {}, messages: {}, groups: {}, sessions: {} };
  }
}
function save() {
  try {
    fs.writeFileSync(DATA, JSON.stringify(db));
  } catch (e) {
    console.error('save failed', e.message);
  }
}

let db = load();
const sockets = new Map();

function normLogin(l) {
  return String(l || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_а-яё]/gi, '')
    .slice(0, 24);
}
function threadKey(a, b) {
  return [a, b].sort().join('|');
}
function tokenFor(login) {
  const t = crypto.randomBytes(24).toString('hex');
  db.sessions[t] = { login, ts: Date.now() };
  // prune old sessions for this user (keep last 5)
  const entries = Object.entries(db.sessions).filter(([, v]) => v.login === login);
  if (entries.length > 5) {
    entries
      .sort((a, b) => a[1].ts - b[1].ts)
      .slice(0, entries.length - 5)
      .forEach(([k]) => delete db.sessions[k]);
  }
  save();
  return t;
}
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : req.query.token || '';
  const sess = db.sessions[t];
  if (!sess || !db.users[sess.login]) {
    return res.status(401).json({ error: 'unauthorized', message: 'Войди заново' });
  }
  req.login = sess.login;
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
  };
}
function push(login, payload) {
  const set = sockets.get(login);
  if (!set) return;
  const raw = JSON.stringify(payload);
  for (const ws of set) {
    try {
      if (ws.readyState === 1) ws.send(raw);
    } catch {}
  }
}
function pushMany(logins, payload) {
  const uniq = [...new Set(logins)];
  uniq.forEach((l) => push(l, payload));
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '12mb' }));

app.get('/', (_, res) => res.type('text').send('Astrix server OK'));
app.get('/api/health', (_, res) =>
  res.json({
    ok: true,
    users: Object.keys(db.users).length,
    groups: Object.keys(db.groups).length,
  })
);

// DEV: wipe all (protected by simple key)
app.post('/api/admin/wipe', (req, res) => {
  const key = (req.body && req.body.key) || req.query.key;
  if (key !== 'astrix-wipe-4242') return res.status(403).json({ error: 'forbidden' });
  db = { users: {}, messages: {}, groups: {}, sessions: {} };
  save();
  res.json({ ok: true, message: 'all cleared' });
});

app.post('/api/register', (req, res) => {
  let login = normLogin(req.body && req.body.login);
  const password = String((req.body && req.body.password) || '');
  const name = String((req.body && req.body.name) || login).slice(0, 24);
  if (login.length < 3) return res.status(400).json({ error: 'bad_login', message: 'Логин от 3 символов' });
  if (password.length < 1) return res.status(400).json({ error: 'bad_password', message: 'Нужен пароль' });
  if (db.users[login]) return res.status(409).json({ error: 'taken', message: 'Логин занят' });
  db.users[login] = {
    password,
    name,
    bio: '',
    color: '#3d8bfd',
    photo: null,
    banner: null,
    bannerType: null,
  };
  const token = tokenFor(login);
  save();
  res.json({ token, user: publicUser(login) });
});

app.post('/api/login', (req, res) => {
  const login = normLogin(req.body && req.body.login);
  const password = String((req.body && req.body.password) || '');
  const u = db.users[login];
  if (!u) return res.status(401).json({ error: 'invalid', message: 'Нет такого аккаунта' });
  if (String(u.password) !== password) return res.status(401).json({ error: 'invalid', message: 'Неверный пароль' });
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
  const u = publicUser(normLogin(req.params.login));
  if (!u) return res.status(404).json({ error: 'not_found' });
  res.json({ user: u });
});

app.patch('/api/me', auth, (req, res) => {
  const u = db.users[req.login];
  if (!u) return res.status(404).json({ error: 'not_found' });
  const b = req.body || {};
  if (b.name != null) u.name = String(b.name).slice(0, 24);
  if (b.bio != null) u.bio = String(b.bio).slice(0, 160);
  if (b.color != null) u.color = String(b.color);
  if (b.photo !== undefined) u.photo = b.photo;
  if (b.banner !== undefined) u.banner = b.banner;
  if (b.bannerType !== undefined) u.bannerType = b.bannerType;
  save();
  res.json({ user: publicUser(req.login) });
});

app.delete('/api/me', auth, (req, res) => {
  const login = req.login;
  Object.keys(db.sessions).forEach((t) => {
    if (db.sessions[t].login === login) delete db.sessions[t];
  });
  Object.keys(db.messages).forEach((key) => {
    if (key.split('|').includes(login)) delete db.messages[key];
  });
  Object.keys(db.groups).forEach((gid) => {
    const g = db.groups[gid];
    g.members = (g.members || []).filter((m) => m !== login);
    if (g.members.length === 0) delete db.groups[gid];
  });
  delete db.users[login];
  save();
  const set = sockets.get(login);
  if (set) {
    for (const ws of set) try { ws.close(); } catch {}
    sockets.delete(login);
  }
  res.json({ ok: true });
});

app.get('/api/chats', auth, (req, res) => {
  const me = req.login;
  const chats = [];
  for (const key of Object.keys(db.messages)) {
    if (key.startsWith('g:')) continue;
    const parts = key.split('|');
    if (!parts.includes(me)) continue;
    const other = parts[0] === me ? parts[1] : parts[0];
    if (!db.users[other]) continue;
    const list = db.messages[key] || [];
    chats.push({ with: other, user: publicUser(other), last: list[list.length - 1] || null, type: 'dm' });
  }
  for (const gid of Object.keys(db.groups)) {
    const g = db.groups[gid];
    if (!(g.members || []).includes(me)) continue;
    const list = db.messages['g:' + gid] || [];
    chats.push({
      with: 'g:' + gid,
      group: { id: gid, name: g.name, members: g.members },
      last: list[list.length - 1] || null,
      type: 'group',
    });
  }
  chats.sort((a, b) => (b.last && b.last.ts ? b.last.ts : 0) - (a.last && a.last.ts ? a.last.ts : 0));
  res.json({ chats });
});

app.get('/api/messages/:with', auth, (req, res) => {
  let other = String(req.params.with || '');
  let key;
  if (other.startsWith('g:')) {
    const gid = other.slice(2);
    const g = db.groups[gid];
    if (!g || !(g.members || []).includes(req.login)) return res.status(403).json({ error: 'forbidden' });
    key = 'g:' + gid;
  } else {
    other = normLogin(other);
    key = threadKey(req.login, other);
  }
  res.json({ messages: db.messages[key] || [] });
});

app.post('/api/messages', auth, (req, res) => {
  let to = String((req.body && req.body.to) || '');
  const text = String((req.body && req.body.text) || '').slice(0, 4000);
  const img = (req.body && req.body.img) || null;
  if (!text && !img) return res.status(400).json({ error: 'empty' });

  let key, recipients;
  if (to.startsWith('g:')) {
    const gid = to.slice(2);
    const g = db.groups[gid];
    if (!g || !(g.members || []).includes(req.login)) return res.status(403).json({ error: 'forbidden' });
    key = 'g:' + gid;
    recipients = g.members.slice();
  } else {
    to = normLogin(to);
    if (!db.users[to]) return res.status(404).json({ error: 'not_found', message: 'Нет пользователя' });
    key = threadKey(req.login, to);
    recipients = [req.login, to];
  }
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
  save();
  pushMany(recipients, { type: 'message', message: msg });
  res.json({ message: msg });
});

// Groups
app.get('/api/groups', auth, (req, res) => {
  const list = Object.keys(db.groups)
    .map((id) => {
      const g = db.groups[id];
      if (!(g.members || []).includes(req.login)) return null;
      return { id, name: g.name, members: g.members, owner: g.owner };
    })
    .filter(Boolean);
  res.json({ groups: list });
});

app.post('/api/groups', auth, (req, res) => {
  const name = String((req.body && req.body.name) || 'Группа').trim().slice(0, 40) || 'Группа';
  let members = Array.isArray(req.body && req.body.members) ? req.body.members.map(normLogin) : [];
  members = members.filter((m) => m && db.users[m] && m !== req.login);
  members = [...new Set([req.login, ...members])];
  const id = crypto.randomBytes(6).toString('hex');
  db.groups[id] = { name, members, owner: req.login, created: Date.now() };
  db.messages['g:' + id] = [];
  save();
  const group = { id, name, members, owner: req.login };
  pushMany(members, { type: 'group', group });
  res.json({ group });
});

app.post('/api/groups/:id/members', auth, (req, res) => {
  const g = db.groups[req.params.id];
  if (!g) return res.status(404).json({ error: 'not_found' });
  if (g.owner !== req.login && !(g.members || []).includes(req.login))
    return res.status(403).json({ error: 'forbidden' });
  const login = normLogin(req.body && req.body.login);
  if (!db.users[login]) return res.status(404).json({ error: 'not_found', message: 'Нет пользователя' });
  if (!g.members.includes(login)) g.members.push(login);
  save();
  pushMany(g.members, { type: 'group', group: { id: req.params.id, name: g.name, members: g.members, owner: g.owner } });
  res.json({ group: { id: req.params.id, name: g.name, members: g.members, owner: g.owner } });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws, req) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    const token = url.searchParams.get('token') || '';
    const sess = db.sessions[token];
    if (!sess || !db.users[sess.login]) {
      ws.close();
      return;
    }
    const login = sess.login;
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
  console.log('Astrix server v2 on port', PORT);
});
