// SHACKLED friends/presence server
// Uses sql.js (pure WebAssembly SQLite) — no native compilation,
// works on any Node version including Node 24 on Render.

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'shackled-dev-secret-change-in-prod';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'shackled.db');

// ---------- Database (sql.js — pure JS, no native build needed) ----------
let db;
let SQL;

async function initDB() {
  const initSqlJs = require('sql.js');
  SQL = await initSqlJs();

  // Load existing DB from disk if present, otherwise create fresh
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS friends (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      friend_id INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at INTEGER DEFAULT (strftime('%s','now')),
      UNIQUE(user_id, friend_id)
    );
  `);

  saveDB(); // write initial state to disk
  // Persist to disk every 30 seconds so data survives restarts
  setInterval(saveDB, 30000);
}

function saveDB() {
  try {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  } catch (e) {
    console.error('DB save error:', e);
  }
}

// sql.js helper: run a query and return all rows as objects
function query(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// sql.js helper: run a query and return first row or null
function queryOne(sql, params = []) {
  const rows = query(sql, params);
  return rows[0] || null;
}

// sql.js helper: run INSERT/UPDATE/DELETE, return { lastInsertRowid, changes }
function run(sql, params = []) {
  db.run(sql, params);
  return {
    lastInsertRowid: db.exec('SELECT last_insert_rowid()')[0]?.values[0][0],
    changes: db.getRowsModified(),
  };
}

// ---------- Express ----------
const app = express();
app.use(cors());
app.use(express.json());

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(auth.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ---------- Auth ----------
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username must be 3-20 characters' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Letters, numbers, underscores only' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const existing = queryOne('SELECT id FROM users WHERE username = ?', [username]);
    if (existing) return res.status(409).json({ error: 'Username already taken' });
    const hash = await bcrypt.hash(password, 10);
    const result = run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash]);
    saveDB();
    const token = jwt.sign({ id: result.lastInsertRowid, username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: result.lastInsertRowid, username } });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = queryOne('SELECT * FROM users WHERE username = ?', [username]);
  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: 'Invalid username or password' });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username } });
});

// ---------- Friends ----------
function getFriends(uid) {
  return query(`
    SELECT u.id, u.username, f.status,
      CASE WHEN f.user_id=? THEN 'sent' ELSE 'received' END as direction
    FROM friends f
    JOIN users u ON u.id = CASE WHEN f.user_id=? THEN f.friend_id ELSE f.user_id END
    WHERE f.user_id=? OR f.friend_id=?
    ORDER BY f.status DESC, u.username ASC
  `, [uid, uid, uid, uid]);
}

app.get('/api/friends', requireAuth, (req, res) => {
  const uid = req.user.id;
  const rows = getFriends(uid);
  res.json(rows.map(r => ({
    ...r,
    online: onlinePlayers.has(r.id),
    inGame: inGamePlayers.has(r.id),
  })));
});

app.post('/api/friends/request', requireAuth, (req, res) => {
  const { username } = req.body || {};
  const target = queryOne('SELECT id, username FROM users WHERE username = ?', [username]);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.id === req.user.id) return res.status(400).json({ error: "Can't add yourself" });

  const existing = queryOne(
    'SELECT * FROM friends WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)',
    [req.user.id, target.id, target.id, req.user.id]
  );
  if (existing) {
    if (existing.status === 'accepted') return res.status(409).json({ error: 'Already friends' });
    if (existing.user_id === target.id) {
      run('UPDATE friends SET status=? WHERE user_id=? AND friend_id=?', ['accepted', target.id, req.user.id]);
      saveDB();
      pushToUser(target.id, { type: 'friend_accepted', username: req.user.username });
      return res.json({ message: 'Friend request accepted' });
    }
    return res.status(409).json({ error: 'Request already sent' });
  }

  run('INSERT OR IGNORE INTO friends (user_id, friend_id, status) VALUES (?, ?, ?)', [req.user.id, target.id, 'pending']);
  saveDB();
  pushToUser(target.id, { type: 'friend_request', from: req.user.username, fromId: req.user.id });
  res.json({ message: 'Request sent' });
});

app.post('/api/friends/accept', requireAuth, (req, res) => {
  const { fromId } = req.body || {};
  const result = run('UPDATE friends SET status=? WHERE user_id=? AND friend_id=? AND status=?', ['accepted', fromId, req.user.id, 'pending']);
  if (!result.changes) return res.status(404).json({ error: 'No pending request' });
  saveDB();
  pushToUser(fromId, { type: 'friend_accepted', username: req.user.username });
  res.json({ message: 'Accepted' });
});

app.post('/api/friends/decline', requireAuth, (req, res) => {
  run('DELETE FROM friends WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)',
    [req.body.fromId, req.user.id, req.user.id, req.body.fromId]);
  saveDB();
  res.json({ message: 'Declined' });
});

app.post('/api/friends/remove', requireAuth, (req, res) => {
  const fid = req.body.friendId;
  run('DELETE FROM friends WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)',
    [req.user.id, fid, fid, req.user.id]);
  saveDB();
  res.json({ message: 'Removed' });
});

app.get('/api/users/search', requireAuth, (req, res) => {
  const q = (req.query.q || '').trim();
  if (q.length < 2) return res.json([]);
  res.json(query('SELECT id, username FROM users WHERE username LIKE ? AND id != ? LIMIT 10', [`%${q}%`, req.user.id]));
});

app.get('/health', (_, res) => res.json({ ok: true, online: onlinePlayers.size }));

// ---------- WebSocket ----------
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const onlinePlayers = new Map();
const inGamePlayers = new Set();

function pushToUser(userId, payload) {
  const ws = onlinePlayers.get(userId);
  if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(payload));
}

function broadcastPresence(userId, username, online) {
  try {
    const friends = getFriends(userId).filter(f => f.status === 'accepted');
    for (const f of friends) {
      pushToUser(f.id, { type: 'presence', userId, username, online, inGame: inGamePlayers.has(userId) });
    }
  } catch (e) { console.error(e); }
}

wss.on('connection', (ws) => {
  let user = null;

  ws.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }

    if (!user) {
      if (msg.type !== 'auth' || !msg.token) return ws.close();
      try { user = jwt.verify(msg.token, JWT_SECRET); }
      catch { ws.close(); return; }
      const old = onlinePlayers.get(user.id);
      if (old?.readyState === WebSocket.OPEN) old.close();
      onlinePlayers.set(user.id, ws);
      broadcastPresence(user.id, user.username, true);
      ws.send(JSON.stringify({ type: 'authed', userId: user.id, username: user.username }));
      return;
    }

    switch (msg.type) {
      case 'invite':
        pushToUser(msg.toId, { type: 'invite', fromId: user.id, fromUsername: user.username, peerCode: msg.peerCode });
        break;
      case 'invite_accept':
        pushToUser(msg.toId, { type: 'invite_accepted', fromId: user.id, fromUsername: user.username, peerCode: msg.peerCode });
        break;
      case 'invite_decline':
        pushToUser(msg.toId, { type: 'invite_declined', fromUsername: user.username });
        break;
      case 'in_game':
        msg.active ? inGamePlayers.add(user.id) : inGamePlayers.delete(user.id);
        broadcastPresence(user.id, user.username, true);
        break;
      case 'ping':
        ws.send(JSON.stringify({ type: 'pong' }));
        break;
    }
  });

  ws.on('close', () => {
    if (!user) return;
    onlinePlayers.delete(user.id);
    inGamePlayers.delete(user.id);
    broadcastPresence(user.id, user.username, false);
  });

  ws.on('error', console.error);
});

// ---------- Start ----------
initDB().then(() => {
  server.listen(PORT, () => console.log(`SHACKLED server on port ${PORT}`));
}).catch(err => {
  console.error('Failed to init DB:', err);
  process.exit(1);
});
