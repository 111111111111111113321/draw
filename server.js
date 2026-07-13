// server.js - simple auth + PostgreSQL-backed drawing board
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');

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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS drawings (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      image_data TEXT,
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);
}

app.use(express.json({ limit: '5mb' }));
app.use(express.static(__dirname, { index: false }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7, httpOnly: true, sameSite: 'lax' }
}));

// --- Auth middleware: every drawing route relies on this, never on client-supplied ids ---
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
    res.json({ ok: true, username });
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
    res.json({ ok: true, username });
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
  res.json({ loggedIn: true, username: req.session.username });
});

// Loads ONLY the logged-in user's own drawing - userId comes from the server session
app.get('/api/drawing', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT image_data FROM drawings WHERE user_id = $1', [req.session.userId]);
  res.json({ image: result.rows[0]?.image_data || null });
});

// Saves ONLY to the logged-in user's own row - a user can never write to someone else's drawing
app.post('/api/drawing', requireAuth, async (req, res) => {
  const { image } = req.body || {};
  if (typeof image !== 'string' || !image.startsWith('data:image/png;base64,')) {
    return res.status(400).json({ error: 'Некорректные данные изображения' });
  }
  await pool.query(
    `INSERT INTO drawings (user_id, image_data, updated_at) VALUES ($1, $2, NOW())
     ON CONFLICT (user_id) DO UPDATE SET image_data = $2, updated_at = NOW()`,
    [req.session.userId, image]
  );
  res.json({ ok: true });
});

initDb()
  .then(() => app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}`)))
  .catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
