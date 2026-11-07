require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { DatabaseSync } = require('node:sqlite'); // Node 22.5+ içinde hazır gelir
const crypto = require('crypto');
const path = require('path');

const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const SECURE = BASE_URL.startsWith('https');

const PROVIDERS = {
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    scope: 'openid email profile',
    extra: { prompt: 'select_account' }, // her seferinde hesap seçtir
    disabled: process.env.GOOGLE_ENABLED !== 'true', // şimdilik pasif
  },
  discord: {
    clientId: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    authUrl: 'https://discord.com/oauth2/authorize',
    tokenUrl: 'https://discord.com/api/oauth2/token',
    scope: 'identify email',
    extra: { prompt: 'consent' },
  },
};

// ---------- VERİTABANI ----------
const db = new DatabaseSync(path.join(__dirname, 'uno.db'));
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email TEXT UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  avatar_url TEXT,
  provider_avatar TEXT,
  provider TEXT NOT NULL DEFAULT 'email',
  google_id TEXT UNIQUE,
  discord_id TEXT UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,            -- 'announcement' | 'update'
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  version TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS banners (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  text TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS admin_sessions (
  token TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS support_tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  visitor TEXT NOT NULL,
  user_id INTEGER,
  username TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',   -- 'open' | 'closed'
  admin_seen INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_tickets_visitor ON support_tickets(visitor, id);
CREATE TABLE IF NOT EXISTS support_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_id INTEGER NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
  sender TEXT NOT NULL,                  -- 'user' | 'admin'
  text TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS pending_signups (
  token TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  email TEXT,
  avatar TEXT,
  suggested_username TEXT,
  expires_at INTEGER NOT NULL
);
`);

const now = () => Date.now();
const rand = (n = 32) => crypto.randomBytes(n).toString('hex');
const DAY = 24 * 3600 * 1000;

function cleanup() {
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now());
  db.prepare('DELETE FROM pending_signups WHERE expires_at < ?').run(now());
  db.prepare('DELETE FROM admin_sessions WHERE expires_at < ?').run(now());
}
setInterval(cleanup, 10 * 60 * 1000);

const publicUser = (u) => ({
  id: u.id,
  username: u.username,
  email: u.email,
  avatar: u.avatar_url || dicebear(u.username),
  providerAvatar: u.provider_avatar || null,
  provider: u.provider,
  createdAt: u.created_at,
});
const dicebear = (seed) => 'https://api.dicebear.com/7.x/bottts/svg?seed=' + encodeURIComponent(seed);

function cookieOpts(maxAge) {
  return { httpOnly: true, sameSite: 'lax', secure: SECURE, maxAge, path: '/' };
}

function startSession(res, userId) {
  const token = rand();
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)').run(token, userId, now() + 30 * DAY);
  res.cookie('uno_session', token, cookieOpts(30 * DAY));
}

function currentUser(req) {
  const token = req.cookies.uno_session;
  if (!token) return null;
  const row = db.prepare(
    'SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?'
  ).get(token, now());
  return row || null;
}

function requireAuth(req, res, next) {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: 'Giriş yapmalısın.' });
  req.user = u;
  next();
}

// ---------- DOĞRULAMA ----------
const USERNAME_RE = /^[A-Za-z0-9_]{3,20}$/;
function validateUsername(u) {
  if (!USERNAME_RE.test(u || '')) return 'Kullanıcı adı 3-20 karakter olmalı (harf, rakam, alt çizgi).';
}
function validatePassword(p) {
  if (typeof p !== 'string' || p.length < 8) return 'Şifre en az 8 karakter olmalı.';
  if (p.length > 100) return 'Şifre çok uzun.';
}
function sanitizeUsername(s) {
  let u = (s || '').replace(/[^A-Za-z0-9_]/g, '').slice(0, 20);
  return u.length >= 3 ? u : '';
}
const usernameTaken = (u, exceptId = 0) =>
  !!db.prepare('SELECT 1 FROM users WHERE username = ? AND id != ?').get(u, exceptId);

// ---------- UYGULAMA ----------
const app = express();
app.use(express.json({ limit: '600kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Basit hız sınırı (şifre denemeleri için)
const hits = new Map();
function rateLimit(key, max, windowMs) {
  const t = now();
  const arr = (hits.get(key) || []).filter((x) => t - x < windowMs);
  arr.push(t);
  hits.set(key, arr);
  return arr.length > max;
}
setInterval(() => hits.clear(), 30 * 60 * 1000);

// ---- OAuth: yönlendirme ----
app.get('/auth/:provider', (req, res) => {
  const p = PROVIDERS[req.params.provider];
  if (!p) return res.status(404).send('Bilinmeyen sağlayıcı');
  if (p.disabled) return res.redirect('/?auth_error=' + encodeURIComponent('Bu giriş yöntemi şu an kapalı.'));
  if (!p.clientId || !p.clientSecret) return res.redirect('/?auth_error=' + encodeURIComponent('Bu giriş yöntemi henüz yapılandırılmadı.'));
  const state = rand(16);
  res.cookie('uno_oauth_state', state, cookieOpts(10 * 60 * 1000));
  const params = new URLSearchParams({
    client_id: p.clientId,
    redirect_uri: `${BASE_URL}/auth/${req.params.provider}/callback`,
    response_type: 'code',
    scope: p.scope,
    state,
    ...p.extra,
  });
  res.redirect(`${p.authUrl}?${params}`);
});

// ---- OAuth: geri dönüş ----
async function fetchProfile(provider, code) {
  const p = PROVIDERS[provider];
  const tokenRes = await fetch(p.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: p.clientId,
      client_secret: p.clientSecret,
      grant_type: 'authorization_code',
      code,
      redirect_uri: `${BASE_URL}/auth/${provider}/callback`,
    }),
  });
  const tok = await tokenRes.json();
  if (!tok.access_token) throw new Error('Token alınamadı: ' + (tok.error || '') + ' ' + (tok.error_description || ''));
  const auth = { Authorization: `Bearer ${tok.access_token}` };

  if (provider === 'google') {
    const r = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', { headers: auth });
    const g = await r.json();
    if (!g.sub) throw new Error('Google profili alınamadı');
    return {
      id: g.sub,
      email: g.email_verified ? g.email : null,
      avatar: g.picture ? g.picture.replace(/=s\d+-c$/, '=s256-c') : null,
      name: g.name || (g.email || '').split('@')[0],
    };
  }
  // discord
  const r = await fetch('https://discord.com/api/users/@me', { headers: auth });
  const d = await r.json();
  if (!d.id) throw new Error('Discord profili alınamadı');
  const avatar = d.avatar
    ? `https://cdn.discordapp.com/avatars/${d.id}/${d.avatar}.${d.avatar.startsWith('a_') ? 'gif' : 'png'}?size=256`
    : `https://cdn.discordapp.com/embed/avatars/${Number((BigInt(d.id) >> 22n) % 6n)}.png`;
  return {
    id: d.id,
    email: d.verified ? d.email : null,
    avatar,
    name: d.global_name || d.username,
  };
}

app.get('/auth/:provider/callback', async (req, res) => {
  const provider = req.params.provider;
  if (!PROVIDERS[provider] || PROVIDERS[provider].disabled) return res.status(404).send('Bilinmeyen sağlayıcı');
  const fail = (m) => res.redirect('/?auth_error=' + encodeURIComponent(m));
  try {
    const { code, state, error } = req.query;
    if (error) { console.error(`[OAuth ${provider}] sağlayıcı hatası:`, error); return fail('Giriş iptal edildi veya reddedildi: ' + error); }
    if (!code || !state || state !== req.cookies.uno_oauth_state) {
      console.error(`[OAuth ${provider}] state uyuşmadı (çerez yok veya farklı)`);
      return fail('Geçersiz istek (state), tekrar dene. Siteyi localhost ile açtığından emin ol.');
    }
    res.clearCookie('uno_oauth_state');

    const prof = await fetchProfile(provider, String(code));
    const idCol = provider === 'google' ? 'google_id' : 'discord_id';

    // 1) Bu sağlayıcıyla daha önce kayıt olmuş mu?
    let user = db.prepare(`SELECT * FROM users WHERE ${idCol} = ?`).get(prof.id);

    // 2) Aynı (doğrulanmış) e-postaya sahip hesap varsa bağla
    if (!user && prof.email) {
      user = db.prepare('SELECT * FROM users WHERE email = ?').get(prof.email);
      if (user) {
        db.prepare(`UPDATE users SET ${idCol} = ?, provider_avatar = COALESCE(provider_avatar, ?) WHERE id = ?`)
          .run(prof.id, prof.avatar, user.id);
      }
    }

    if (user) {
      // Sağlayıcı pp'si güncellendiyse ve kullanıcı sağlayıcı pp'sini kullanıyorsa yenile
      if (user.provider === provider && user.avatar_url === user.provider_avatar && prof.avatar) {
        db.prepare('UPDATE users SET avatar_url = ?, provider_avatar = ? WHERE id = ?').run(prof.avatar, prof.avatar, user.id);
      }
      startSession(res, user.id);
      return res.redirect('/?welcome=back');
    }

    // 3) Yeni kullanıcı -> isim/şifre seçme ekranı
    const token = rand();
    db.prepare(
      'INSERT INTO pending_signups (token, provider, provider_id, email, avatar, suggested_username, expires_at) VALUES (?,?,?,?,?,?,?)'
    ).run(token, provider, prof.id, prof.email, prof.avatar, sanitizeUsername(prof.name), now() + 15 * 60 * 1000);
    res.cookie('uno_pending', token, cookieOpts(15 * 60 * 1000));
    res.redirect('/');
  } catch (e) {
    console.error(`[OAuth ${provider}]`, e);
    fail('Giriş hatası: ' + String(e.message || e).slice(0, 150));
  }
});

// ---- API ----
app.get('/api/config', (req, res) => {
  res.json({ google: !PROVIDERS.google.disabled && !!PROVIDERS.google.clientId, discord: !!PROVIDERS.discord.clientId });
});

app.get('/api/me', (req, res) => {
  const u = currentUser(req);
  if (u) return res.json({ user: publicUser(u) });
  const pt = req.cookies.uno_pending;
  if (pt) {
    const p = db.prepare('SELECT * FROM pending_signups WHERE token = ? AND expires_at > ?').get(pt, now());
    if (p) {
      return res.json({
        pending: { provider: p.provider, email: p.email, avatar: p.avatar, suggestedUsername: p.suggested_username },
      });
    }
  }
  res.json({});
});

// Sosyal girişten sonra isim + şifre seçerek hesabı tamamla
app.post('/api/auth/complete-signup', (req, res) => {
  const pt = req.cookies.uno_pending;
  const p = pt && db.prepare('SELECT * FROM pending_signups WHERE token = ? AND expires_at > ?').get(pt, now());
  if (!p) return res.status(400).json({ error: 'Oturum süresi doldu, tekrar giriş yap.' });

  const { username, password } = req.body || {};
  const err = validateUsername(username) || validatePassword(password);
  if (err) return res.status(400).json({ error: err });
  if (usernameTaken(username)) return res.status(409).json({ error: 'Bu kullanıcı adı alınmış.' });

  const idCol = p.provider === 'google' ? 'google_id' : 'discord_id';
  const hash = bcrypt.hashSync(password, 10);
  try {
    const info = db.prepare(
      `INSERT INTO users (username, email, password_hash, avatar_url, provider_avatar, provider, ${idCol}) VALUES (?,?,?,?,?,?,?)`
    ).run(username, p.email, hash, p.avatar, p.avatar, p.provider, p.provider_id);
    db.prepare('DELETE FROM pending_signups WHERE token = ?').run(pt);
    res.clearCookie('uno_pending');
    startSession(res, info.lastInsertRowid);
    res.json({ user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid)) });
  } catch (e) {
    res.status(409).json({ error: 'Bu e-posta veya kullanıcı adı zaten kayıtlı.' });
  }
});

app.post('/api/auth/cancel-signup', (req, res) => {
  const pt = req.cookies.uno_pending;
  if (pt) db.prepare('DELETE FROM pending_signups WHERE token = ?').run(pt);
  res.clearCookie('uno_pending');
  res.json({ ok: true });
});

// E-posta ile kayıt
app.post('/api/auth/register', (req, res) => {
  const { username, email, password } = req.body || {};
  const err = validateUsername(username) || validatePassword(password);
  if (err) return res.status(400).json({ error: err });
  if (!/^\S+@\S+\.\S+$/.test(email || '')) return res.status(400).json({ error: 'Geçerli bir e-posta gir.' });
  if (usernameTaken(username)) return res.status(409).json({ error: 'Bu kullanıcı adı alınmış.' });
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) return res.status(409).json({ error: 'Bu e-posta zaten kayıtlı.' });

  const info = db.prepare(
    'INSERT INTO users (username, email, password_hash, avatar_url, provider) VALUES (?,?,?,?,?)'
  ).run(username, email, bcrypt.hashSync(password, 10), dicebear(username), 'email');
  startSession(res, info.lastInsertRowid);
  res.json({ user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid)) });
});

// E-posta / kullanıcı adı ile giriş
app.post('/api/auth/login', (req, res) => {
  const { identifier, password } = req.body || {};
  if (rateLimit('login:' + req.ip, 10, 10 * 60 * 1000)) {
    return res.status(429).json({ error: 'Çok fazla deneme. Biraz sonra tekrar dene.' });
  }
  const u = db.prepare('SELECT * FROM users WHERE email = ? OR username = ?').get(identifier || '', identifier || '');
  if (!u || !bcrypt.compareSync(String(password || ''), u.password_hash)) {
    return res.status(401).json({ error: 'Kullanıcı adı/e-posta veya şifre hatalı!' });
  }
  startSession(res, u.id);
  res.json({ user: publicUser(u) });
});

app.post('/api/logout', (req, res) => {
  const t = req.cookies.uno_session;
  if (t) db.prepare('DELETE FROM sessions WHERE token = ?').run(t);
  res.clearCookie('uno_session');
  res.json({ ok: true });
});

// Profil düzenleme: kullanıcı adı + avatar
app.patch('/api/profile', requireAuth, (req, res) => {
  const { username, avatarMode, avatarData } = req.body || {};
  const u = req.user;
  let newName = u.username;
  let newAvatar = u.avatar_url;

  if (username !== undefined && username !== u.username) {
    const err = validateUsername(username);
    if (err) return res.status(400).json({ error: err });
    if (usernameTaken(username, u.id)) return res.status(409).json({ error: 'Bu kullanıcı adı alınmış.' });
    newName = username;
  }

  if (avatarMode === 'provider') {
    if (!u.provider_avatar) return res.status(400).json({ error: 'Bağlı bir hesabın profil fotoğrafı yok.' });
    newAvatar = u.provider_avatar;
  } else if (avatarMode === 'default') {
    newAvatar = dicebear(newName);
  } else if (avatarMode === 'custom') {
    if (typeof avatarData !== 'string' || !/^data:image\/(jpeg|png|webp);base64,/.test(avatarData) || avatarData.length > 400000) {
      return res.status(400).json({ error: 'Geçersiz veya çok büyük görsel.' });
    }
    newAvatar = avatarData;
  }

  db.prepare('UPDATE users SET username = ?, avatar_url = ? WHERE id = ?').run(newName, newAvatar, u.id);
  res.json({ user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(u.id)) });
});

// Şifre değiştirme
app.post('/api/profile/password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!bcrypt.compareSync(String(currentPassword || ''), req.user.password_hash)) {
    return res.status(401).json({ error: 'Mevcut şifre hatalı.' });
  }
  const err = validatePassword(newPassword);
  if (err) return res.status(400).json({ error: err });
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(newPassword, 10), req.user.id);
  res.json({ ok: true });
});

// =====================================================================
//  SİTE İÇERİĞİ (herkese açık): duyurular, güncellemeler, indirim bandı
// =====================================================================
app.get('/api/site', (req, res) => {
  const posts = (kind) =>
    db.prepare('SELECT id, title, body, version, created_at FROM posts WHERE kind = ? ORDER BY id DESC LIMIT 10').all(kind);
  res.json({
    announcements: posts('announcement'),
    updates: posts('update'),
    banners: db.prepare('SELECT id, text FROM banners ORDER BY id ASC').all(),
  });
});

// =====================================================================
//  CANLI DESTEK (ziyaretçi tarafı)
// =====================================================================
function visitorId(req, res) {
  let v = req.cookies.uno_visitor;
  if (!v || !/^[a-f0-9]{32}$/.test(v)) {
    v = rand(16);
    res.cookie('uno_visitor', v, { httpOnly: true, sameSite: 'lax', secure: SECURE, maxAge: 365 * DAY, path: '/' });
  }
  return v;
}

function supportState(visitor) {
  const t = db.prepare('SELECT * FROM support_tickets WHERE visitor = ? ORDER BY id DESC LIMIT 1').get(visitor);
  if (!t) return { ticket: null, messages: [] };
  const messages = db.prepare(
    'SELECT id, sender, text, created_at FROM support_messages WHERE ticket_id = ? ORDER BY id ASC LIMIT 300'
  ).all(t.id);
  return { ticket: { id: t.id, status: t.status }, messages };
}

app.get('/api/support', (req, res) => {
  res.json(supportState(visitorId(req, res)));
});

app.post('/api/support/message', (req, res) => {
  const v = visitorId(req, res);
  const text = String((req.body && req.body.text) || '').trim();
  if (!text) return res.status(400).json({ error: 'Mesaj boş olamaz.' });
  if (text.length > 1000) return res.status(400).json({ error: 'Mesaj çok uzun (en fazla 1000 karakter).' });
  if (rateLimit('support:' + v, 20, 60 * 1000)) return res.status(429).json({ error: 'Çok hızlı mesaj gönderiyorsun.' });

  let t = db.prepare('SELECT * FROM support_tickets WHERE visitor = ? ORDER BY id DESC LIMIT 1').get(v);
  if (!t || t.status !== 'open') {
    const u = currentUser(req);
    const info = db.prepare('INSERT INTO support_tickets (visitor, user_id, username) VALUES (?,?,?)')
      .run(v, u ? u.id : null, u ? u.username : 'Misafir');
    t = { id: Number(info.lastInsertRowid) };
  }
  db.prepare('INSERT INTO support_messages (ticket_id, sender, text) VALUES (?,?,?)').run(t.id, 'user', text);
  res.json(supportState(v));
});

// =====================================================================
//  ADMİN PANELİ
// =====================================================================
const ADMIN_USER = process.env.ADMIN_USER || 'zetastore';
const ADMIN_PASS = process.env.ADMIN_PASS || 'zetastore123**A';
const sha = (x) => crypto.createHash('sha256').update(String(x)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

function isAdmin(req) {
  const t = req.cookies.uno_admin;
  if (!t) return false;
  return !!db.prepare('SELECT 1 FROM admin_sessions WHERE token = ? AND expires_at > ?').get(t, now());
}
function requireAdmin(req, res, next) {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Yetkisiz.' });
  next();
}
const idParam = (req) => {
  const n = Number(req.params.id);
  return Number.isInteger(n) && n > 0 ? n : null;
};

app.get('/adminpanel', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.sendFile(path.join(__dirname, 'views', 'adminpanel.html'));
});

app.post('/api/admin/login', (req, res) => {
  if (rateLimit('admin:' + req.ip, 8, 10 * 60 * 1000)) {
    return res.status(429).json({ error: 'Çok fazla deneme. 10 dakika sonra tekrar dene.' });
  }
  const { username, password } = req.body || {};
  const ok = safeEq(username || '', ADMIN_USER) & safeEq(password || '', ADMIN_PASS);
  if (!ok) return res.status(401).json({ error: 'İsim veya şifre hatalı.' });
  const token = rand();
  db.prepare('INSERT INTO admin_sessions (token, expires_at) VALUES (?,?)').run(token, now() + 12 * 3600 * 1000);
  res.cookie('uno_admin', token, { httpOnly: true, sameSite: 'strict', secure: SECURE, maxAge: 12 * 3600 * 1000, path: '/' });
  res.json({ ok: true });
});

app.post('/api/admin/logout', (req, res) => {
  const t = req.cookies.uno_admin;
  if (t) db.prepare('DELETE FROM admin_sessions WHERE token = ?').run(t);
  res.clearCookie('uno_admin');
  res.json({ ok: true });
});

app.get('/api/admin/me', (req, res) => res.json({ admin: isAdmin(req) }));

app.get('/api/admin/overview', requireAdmin, (req, res) => {
  const c = (sql) => db.prepare(sql).get().n;
  res.json({
    users: c('SELECT COUNT(*) AS n FROM users'),
    announcements: c("SELECT COUNT(*) AS n FROM posts WHERE kind = 'announcement'"),
    updates: c("SELECT COUNT(*) AS n FROM posts WHERE kind = 'update'"),
    banners: c('SELECT COUNT(*) AS n FROM banners'),
    openTickets: c("SELECT COUNT(*) AS n FROM support_tickets WHERE status = 'open'"),
    unreadTickets: c(`SELECT COUNT(*) AS n FROM support_tickets t WHERE t.status = 'open' AND EXISTS
      (SELECT 1 FROM support_messages m WHERE m.ticket_id = t.id AND m.sender = 'user' AND m.id > t.admin_seen)`),
  });
});

// ---- kullanıcılar ----
app.get('/api/admin/users', requireAdmin, (req, res) => {
  res.json({
    users: db.prepare(
      'SELECT id, username, email, avatar_url AS avatar, provider, created_at FROM users ORDER BY id DESC LIMIT 1000'
    ).all(),
  });
});
app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = idParam(req);
  if (!id) return res.status(400).json({ error: 'Geçersiz id.' });
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.json({ ok: true });
});

// ---- duyurular & güncellemeler ----
app.get('/api/admin/posts', requireAdmin, (req, res) => {
  const kind = req.query.kind === 'update' ? 'update' : 'announcement';
  res.json({ posts: db.prepare('SELECT id, title, body, version, created_at FROM posts WHERE kind = ? ORDER BY id DESC').all(kind) });
});
app.post('/api/admin/posts', requireAdmin, (req, res) => {
  const { kind, title, body, version } = req.body || {};
  if (kind !== 'announcement' && kind !== 'update') return res.status(400).json({ error: 'Geçersiz tür.' });
  const t = String(title || '').trim(), b = String(body || '').trim(), v = String(version || '').trim();
  if (!t || t.length > 100) return res.status(400).json({ error: 'Başlık gerekli (en fazla 100 karakter).' });
  if (!b || b.length > 3000) return res.status(400).json({ error: 'İçerik gerekli (en fazla 3000 karakter).' });
  if (v.length > 20) return res.status(400).json({ error: 'Sürüm en fazla 20 karakter.' });
  db.prepare('INSERT INTO posts (kind, title, body, version) VALUES (?,?,?,?)').run(kind, t, b, kind === 'update' ? v || null : null);
  res.json({ ok: true });
});
app.delete('/api/admin/posts/:id', requireAdmin, (req, res) => {
  const id = idParam(req);
  if (!id) return res.status(400).json({ error: 'Geçersiz id.' });
  db.prepare('DELETE FROM posts WHERE id = ?').run(id);
  res.json({ ok: true });
});

// ---- indirim bandı ----
app.get('/api/admin/banners', requireAdmin, (req, res) => {
  res.json({ banners: db.prepare('SELECT id, text, created_at FROM banners ORDER BY id DESC').all() });
});
app.post('/api/admin/banners', requireAdmin, (req, res) => {
  const text = String((req.body && req.body.text) || '').trim();
  if (!text || text.length > 250) return res.status(400).json({ error: 'Metin gerekli (en fazla 250 karakter).' });
  db.prepare('INSERT INTO banners (text) VALUES (?)').run(text);
  res.json({ ok: true });
});
app.delete('/api/admin/banners/:id', requireAdmin, (req, res) => {
  const id = idParam(req);
  if (!id) return res.status(400).json({ error: 'Geçersiz id.' });
  db.prepare('DELETE FROM banners WHERE id = ?').run(id);
  res.json({ ok: true });
});

// ---- canlı destek (admin tarafı) ----
app.get('/api/admin/tickets', requireAdmin, (req, res) => {
  res.json({
    tickets: db.prepare(`
      SELECT t.id, t.username, t.user_id, t.created_at,
        (SELECT text FROM support_messages WHERE ticket_id = t.id ORDER BY id DESC LIMIT 1) AS last_text,
        (SELECT COUNT(*) FROM support_messages m WHERE m.ticket_id = t.id AND m.sender = 'user' AND m.id > t.admin_seen) AS unread
      FROM support_tickets t WHERE t.status = 'open' ORDER BY t.id ASC`).all(),
  });
});
app.get('/api/admin/tickets/:id', requireAdmin, (req, res) => {
  const id = idParam(req);
  const t = id && db.prepare('SELECT id, username, user_id, status, created_at FROM support_tickets WHERE id = ?').get(id);
  if (!t) return res.status(404).json({ error: 'Destek bulunamadı.' });
  const messages = db.prepare('SELECT id, sender, text, created_at FROM support_messages WHERE ticket_id = ? ORDER BY id ASC LIMIT 500').all(id);
  if (messages.length) {
    db.prepare('UPDATE support_tickets SET admin_seen = ? WHERE id = ?').run(messages[messages.length - 1].id, id);
  }
  res.json({ ticket: t, messages });
});
app.post('/api/admin/tickets/:id/messages', requireAdmin, (req, res) => {
  const id = idParam(req);
  const t = id && db.prepare('SELECT * FROM support_tickets WHERE id = ?').get(id);
  if (!t) return res.status(404).json({ error: 'Destek bulunamadı.' });
  if (t.status !== 'open') return res.status(400).json({ error: 'Bu destek kapatılmış.' });
  const text = String((req.body && req.body.text) || '').trim();
  if (!text || text.length > 1000) return res.status(400).json({ error: 'Mesaj boş veya çok uzun.' });
  const info = db.prepare('INSERT INTO support_messages (ticket_id, sender, text) VALUES (?,?,?)').run(id, 'admin', text);
  db.prepare('UPDATE support_tickets SET admin_seen = ? WHERE id = ?').run(Number(info.lastInsertRowid), id);
  res.json({ ok: true });
});
app.post('/api/admin/tickets/:id/close', requireAdmin, (req, res) => {
  const id = idParam(req);
  if (!id) return res.status(400).json({ error: 'Geçersiz id.' });
  db.prepare("UPDATE support_tickets SET status = 'closed' WHERE id = ?").run(id);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`UNO Online çalışıyor: ${BASE_URL}`);
  console.log('Admin paneli        :', `${BASE_URL}/adminpanel`);
  console.log('Google              :', PROVIDERS.google.disabled ? 'PASİF' : `aktif (${BASE_URL}/auth/google/callback)`);
  console.log('Discord redirect URI:', `${BASE_URL}/auth/discord/callback`, PROVIDERS.discord.clientId ? '(anahtar var)' : '(ANAHTAR YOK)');
});
