// server.js - auth + realtime shared infinite canvas (PostgreSQL + WebSocket)
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/aero'
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  // Every user draws on the SAME shared canvas now. Each stroke is a single
  // line segment in world coordinates (the canvas has no bounds).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS strokes (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      x1 DOUBLE PRECISION NOT NULL,
      y1 DOUBLE PRECISION NOT NULL,
      x2 DOUBLE PRECISION NOT NULL,
      y2 DOUBLE PRECISION NOT NULL,
      color TEXT NOT NULL,
      size REAL NOT NULL,
      tool TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
}

app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname, { index: false }));

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7, httpOnly: true, sameSite: 'lax' }
});
app.use(sessionMiddleware);

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Требуется вход в систему' });
  next();
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password || username.length < 3 || password.length < 6) {
    return res.status(400).json({ error: 'Имя пользователя минимум 3 символа, пароль минимум 6 символов' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id',
      [username, hash]
    );
    req.session.userId = result.rows[0].id;
    req.session.username = username;
    res.json({ ok: true, username, id: req.session.userId });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Это имя пользователя уже занято' });
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  try {
    const result = await pool.query('SELECT id, password_hash FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Неверные учётные данные' });
    const user = result.rows[0];
    const match = await bcrypt.compare(password || '', user.password_hash);
    if (!match) return res.status(401).json({ error: 'Неверные учётные данные' });
    req.session.userId = user.id;
    req.session.username = username;
    res.json({ ok: true, username, id: user.id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, username: req.session.username, id: req.session.userId });
});

// ---------- realtime shared canvas over WebSocket ----------
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

// Reuse the same express session on the WebSocket handshake so only logged-in
// users can open a socket and draw. The userId always comes from the session,
// never from anything the client sends.
server.on('upgrade', (req, socket, head) => {
  sessionMiddleware(req, {}, () => {
    if (!req.session || !req.session.userId) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, ws => {
      ws.userId = req.session.userId;
      wss.emit('connection', ws, req);
    });
  });
});

// ---------- ownership: nobody may draw or erase over territory someone else already drew on ----------
// The infinite canvas is divided into a grid. The first PEN stroke to touch a cell claims it
// for that user. From then on, only that user may draw or erase in that cell. Erasing never
// claims new territory itself - it can only act on cells you already own or that are still empty.
const CELL_SIZE = 40;
const cellOwners = new Map(); // "cx,cy" -> user_id

function cellKey(cx, cy) { return cx + ',' + cy; }

function cellsForSegment(x1, y1, x2, y2) {
  const pts = [[x1, y1], [x2, y2], [(x1 + x2) / 2, (y1 + y2) / 2]];
  const cells = new Set();
  for (const [x, y] of pts) cells.add(cellKey(Math.floor(x / CELL_SIZE), Math.floor(y / CELL_SIZE)));
  return [...cells];
}

function canClaim(cells, userId) {
  for (const c of cells) {
    const owner = cellOwners.get(c);
    if (owner !== undefined && owner !== userId) return false;
  }
  return true;
}

function claimCells(cells, userId) {
  for (const c of cells) if (!cellOwners.has(c)) cellOwners.set(c, userId);
}

async function rebuildCellOwnership() {
  const result = await pool.query('SELECT x1, y1, x2, y2, tool, user_id FROM strokes ORDER BY id ASC');
  for (const row of result.rows) {
    if (row.tool === 'eraser') continue; // erasing never claims territory
    claimCells(cellsForSegment(row.x1, row.y1, row.x2, row.y2), row.user_id);
  }
}

function isValidStroke(s) {
  const nums = [s.x1, s.y1, s.x2, s.y2, s.size];
  if (nums.some(n => typeof n !== 'number' || !isFinite(n))) return false;
  if (s.size <= 0 || s.size > 300) return false;
  if (s.tool !== 'pen' && s.tool !== 'eraser') return false;
  if (typeof s.color !== 'string' || !/^(#[0-9a-fA-F]{6}|rgb\(\d{1,3},\d{1,3},\d{1,3}\))$/.test(s.color)) return false;
  return true;
}

function broadcast(obj, exceptWs) {
  const data = JSON.stringify(obj);
  wss.clients.forEach(client => {
    if (client !== exceptWs && client.readyState === WebSocket.OPEN) client.send(data);
  });
}

wss.on('connection', async ws => {
  try {
    const result = await pool.query(
      'SELECT id, x1, y1, x2, y2, color, size, tool, user_id FROM strokes ORDER BY id ASC'
    );
    ws.send(JSON.stringify({ type: 'history', strokes: result.rows }));
  } catch (err) {
    console.error('Failed to load history:', err);
  }

  ws.on('message', async raw => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'stroke' && isValidStroke(msg)) {
      const cells = cellsForSegment(msg.x1, msg.y1, msg.x2, msg.y2);
      if (!canClaim(cells, ws.userId)) {
        ws.send(JSON.stringify({ type: 'rejected' }));
        return;
      }
      // Claim synchronously, before any await, so two near-simultaneous strokes can't both pass the check.
      if (msg.tool !== 'eraser') claimCells(cells, ws.userId);
      try {
        const result = await pool.query(
          `INSERT INTO strokes (user_id, x1, y1, x2, y2, color, size, tool)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
          [ws.userId, msg.x1, msg.y1, msg.x2, msg.y2, msg.color, msg.size, msg.tool]
        );
        broadcast({
          type: 'stroke', id: result.rows[0].id,
          x1: msg.x1, y1: msg.y1, x2: msg.x2, y2: msg.y2,
          color: msg.color, size: msg.size, tool: msg.tool, user_id: ws.userId
        }, ws);
      } catch (err) {
        console.error('Failed to save stroke:', err);
      }
    } else if (msg.type === 'clear') {
      try {
        await pool.query('DELETE FROM strokes');
        cellOwners.clear();
        broadcast({ type: 'clear' }, ws);
      } catch (err) {
        console.error('Failed to clear canvas:', err);
      }
    }
  });
});

initDb()
  .then(rebuildCellOwnership)
  .then(() => server.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}`)))
  .catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
