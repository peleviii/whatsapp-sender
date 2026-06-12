const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const Database = require('better-sqlite3');
const { Client, LocalAuth, MessageMedia } = require('whatsapp-web.js');
const QRCode = require('qrcode');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const JWT_SECRET  = process.env.JWT_SECRET  || 'change-me-in-production';
const ADMIN_KEY   = process.env.ADMIN_KEY   || 'admin-secret';
const TOKEN_COOKIE = 'wa_token';
const DAILY_LIMIT = parseInt(process.env.DAILY_LIMIT || '300', 10); // μέγιστα μηνύματα/μέρα ανά χρήστη

// ── DB ────────────────────────────────────────────────────────────────────────
const db = new Database('/app/data/contacts.db');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT NOT NULL UNIQUE,
    password          TEXT NOT NULL,
    phone             TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    trial_ends_at     TEXT NOT NULL,
    plan              TEXT NOT NULL DEFAULT 'trial',
    subscription_until TEXT,
    per_use_credits   INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS groups (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name    TEXT NOT NULL,
    UNIQUE(user_id, name)
  );
  CREATE TABLE IF NOT EXISTS contacts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    last_name  TEXT NOT NULL DEFAULT '',
    phone      TEXT NOT NULL,
    salutation TEXT NOT NULL DEFAULT '',
    group_id   INTEGER REFERENCES groups(id) ON DELETE SET NULL,
    UNIQUE(user_id, phone)
  );
  CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    media_name TEXT NOT NULL DEFAULT '',
    sent_at    TEXT NOT NULL DEFAULT (datetime('now')),
    total      INTEGER NOT NULL DEFAULT 0,
    ok         INTEGER NOT NULL DEFAULT 0,
    fail       INTEGER NOT NULL DEFAULT 0,
    recipients TEXT NOT NULL DEFAULT '[]'
  );
  CREATE TABLE IF NOT EXISTS daily_counts (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    day     TEXT NOT NULL,
    count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day)
  );
  CREATE TABLE IF NOT EXISTS scheduled (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body           TEXT NOT NULL DEFAULT '',
    media_name     TEXT NOT NULL DEFAULT '',
    media_mimetype TEXT NOT NULL DEFAULT '',
    media_data     TEXT NOT NULL DEFAULT '',
    contact_ids    TEXT NOT NULL DEFAULT '[]',
    scheduled_at   TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    error          TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Migrations: προσθήκη στηλών σε υπάρχουσες βάσεις (χωρίς απώλεια δεδομένων)
const contactCols = db.prepare('PRAGMA table_info(contacts)').all();
if (!contactCols.some(c => c.name === 'salutation')) {
  db.exec("ALTER TABLE contacts ADD COLUMN salutation TEXT NOT NULL DEFAULT ''");
}
if (!contactCols.some(c => c.name === 'group_id')) {
  db.exec('ALTER TABLE contacts ADD COLUMN group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL');
}
if (!contactCols.some(c => c.name === 'last_name')) {
  db.exec("ALTER TABLE contacts ADD COLUMN last_name TEXT NOT NULL DEFAULT ''");
}
const userCols = db.prepare('PRAGMA table_info(users)').all();
if (!userCols.some(c => c.name === 'phone')) {
  db.exec("ALTER TABLE users ADD COLUMN phone TEXT NOT NULL DEFAULT ''");
}
const msgCols = db.prepare('PRAGMA table_info(messages)').all();
if (!msgCols.some(c => c.name === 'media_name')) {
  db.exec("ALTER TABLE messages ADD COLUMN media_name TEXT NOT NULL DEFAULT ''");
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function addMonths(dateStr, n) {
  const d = new Date(dateStr);
  d.setMonth(d.getMonth() + n);
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

function now() { return new Date().toISOString().slice(0, 19).replace('T', ' '); }

// ── Ημερήσιο όριο αποστολών (anti-ban) ───────────────────────────────────────
function todayStr() { return new Date().toISOString().slice(0, 10); }
function sentToday(userId) {
  const r = db.prepare('SELECT count FROM daily_counts WHERE user_id=? AND day=?').get(userId, todayStr());
  return r ? r.count : 0;
}
const incSentStmt = db.prepare(`
  INSERT INTO daily_counts (user_id, day, count) VALUES (?, ?, 1)
  ON CONFLICT(user_id, day) DO UPDATE SET count = count + 1
`);
function incSent(userId) { incSentStmt.run(userId, todayStr()); }

function accessStatus(user) {
  const n = new Date();
  if (user.plan === 'yearly' && user.subscription_until && new Date(user.subscription_until) > n)
    return { ok: true, plan: 'yearly', until: user.subscription_until };
  if (user.plan === 'trial' && new Date(user.trial_ends_at) > n)
    return { ok: true, plan: 'trial', until: user.trial_ends_at };
  if (user.plan === 'per_use' && user.per_use_credits > 0)
    return { ok: true, plan: 'per_use', credits: user.per_use_credits };
  return { ok: false, plan: user.plan };
}

// ── Express ───────────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: '25mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth middleware ───────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.cookies[TOKEN_COOKIE] || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY)
    return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ── Auth routes ───────────────────────────────────────────────────────────────
// Rate limit: μέγιστο 10 αποτυχημένες προσπάθειες ανά IP ανά 15 λεπτά
const loginAttempts = new Map();
function tooManyAttempts(ip) {
  const rec = loginAttempts.get(ip);
  return rec && Date.now() < rec.resetAt && rec.count >= 10;
}
function recordFailedAttempt(ip) {
  let rec = loginAttempts.get(ip);
  if (!rec || Date.now() > rec.resetAt) {
    rec = { count: 0, resetAt: Date.now() + 15 * 60 * 1000 };
    loginAttempts.set(ip, rec);
  }
  rec.count++;
}
setInterval(() => {
  for (const [ip, rec] of loginAttempts) if (Date.now() > rec.resetAt) loginAttempts.delete(ip);
}, 10 * 60 * 1000);

app.post('/api/register', (req, res) => {
  if (tooManyAttempts(req.ip))
    return res.status(429).json({ error: 'Πολλές προσπάθειες. Δοκίμασε ξανά σε 15 λεπτά.' });
  const { username, password, phone } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Απαιτούνται username και password' });
  if (username.length < 3) return res.status(400).json({ error: 'Το username πρέπει να έχει τουλάχιστον 3 χαρακτήρες' });
  if (password.length < 6) return res.status(400).json({ error: 'Ο κωδικός πρέπει να έχει τουλάχιστον 6 χαρακτήρες' });
  const phoneDigits = (phone || '').replace(/[\s\-\(\)\+]/g, '');
  if (phoneDigits.length < 10) return res.status(400).json({ error: 'Απαιτείται έγκυρο τηλέφωνο επικοινωνίας' });

  const hash = bcrypt.hashSync(password, 10);
  const trialEnd = addMonths(now(), 1);
  try {
    const r = db.prepare(
      'INSERT INTO users (username, password, phone, trial_ends_at) VALUES (?, ?, ?, ?)'
    ).run(username, hash, phoneDigits, trialEnd);
    const user = { id: r.lastInsertRowid, username };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '30d' });
    res.cookie(TOKEN_COOKIE, token, { httpOnly: true, maxAge: 30 * 24 * 3600 * 1000 });
    res.json({ ok: true, username });
  } catch {
    recordFailedAttempt(req.ip);
    res.status(409).json({ error: 'Το username χρησιμοποιείται ήδη' });
  }
});

app.post('/api/login', (req, res) => {
  if (tooManyAttempts(req.ip))
    return res.status(429).json({ error: 'Πολλές προσπάθειες. Δοκίμασε ξανά σε 15 λεπτά.' });
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    recordFailedAttempt(req.ip);
    return res.status(401).json({ error: 'Λάθος username ή password' });
  }
  loginAttempts.delete(req.ip);
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie(TOKEN_COOKIE, token, { httpOnly: true, maxAge: 30 * 24 * 3600 * 1000 });
  res.json({ ok: true, username: user.username });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(TOKEN_COOKIE);
  res.json({ ok: true });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const status = accessStatus(user);
  res.json({
    id: user.id,
    username: user.username,
    created_at: user.created_at,
    trial_ends_at: user.trial_ends_at,
    plan: user.plan,
    subscription_until: user.subscription_until,
    per_use_credits: user.per_use_credits,
    access: status,
    daily_used: sentToday(user.id),
    daily_limit: DAILY_LIMIT,
  });
});

app.get('/api/token', authMiddleware, (req, res) => {
  const token = jwt.sign({ id: req.user.id, username: req.user.username }, JWT_SECRET, { expiresIn: '5m' });
  res.json({ token });
});

// ── Admin routes ──────────────────────────────────────────────────────────────
// Activate yearly plan (παλιό endpoint — παραμένει για συμβατότητα)
app.post('/api/admin/activate', adminMiddleware, (req, res) => {
  const { username, plan, months, credits } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (plan === 'yearly') {
    const base = (user.subscription_until && new Date(user.subscription_until) > new Date())
      ? user.subscription_until : now();
    const until = addMonths(base, months || 12);
    db.prepare("UPDATE users SET plan='yearly', subscription_until=? WHERE id=?").run(until, user.id);
    return res.json({ ok: true, plan: 'yearly', until });
  }

  if (plan === 'per_use') {
    const add = credits || 1;
    db.prepare("UPDATE users SET plan='per_use', per_use_credits=per_use_credits+? WHERE id=?").run(add, user.id);
    return res.json({ ok: true, plan: 'per_use', credits: user.per_use_credits + add });
  }

  res.status(400).json({ error: 'plan must be yearly or per_use' });
});

// ΝΕΟ: Πλήρης ενημέρωση χρήστη — πλάνο, χειροκίνητη ημερομηνία λήξης, credits
// body: { username, plan: 'trial'|'yearly'|'per_use', until: 'YYYY-MM-DD', credits: number }
app.post('/api/admin/update-user', adminMiddleware, (req, res) => {
  const { username, plan, until, credits } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (!['trial', 'yearly', 'per_use'].includes(plan))
    return res.status(400).json({ error: 'plan must be trial, yearly or per_use' });

  if (plan === 'per_use') {
    const c = parseInt(credits, 10);
    if (isNaN(c) || c < 0) return res.status(400).json({ error: 'credits must be a number >= 0' });
    db.prepare("UPDATE users SET plan='per_use', per_use_credits=? WHERE id=?").run(c, user.id);
  } else {
    if (!until || !/^\d{4}-\d{2}-\d{2}$/.test(until))
      return res.status(400).json({ error: 'until must be a date in YYYY-MM-DD format' });
    const untilSql = `${until} 23:59:59`;
    if (plan === 'yearly') {
      db.prepare("UPDATE users SET plan='yearly', subscription_until=? WHERE id=?").run(untilSql, user.id);
    } else {
      db.prepare("UPDATE users SET plan='trial', trial_ends_at=? WHERE id=?").run(untilSql, user.id);
    }
  }

  const updated = db.prepare('SELECT id, username, created_at, trial_ends_at, plan, subscription_until, per_use_credits FROM users WHERE id=?').get(user.id);
  res.json({ ok: true, user: { ...updated, access: accessStatus(updated) } });
});

// ΝΕΟ: Διαγραφή χρήστη (μαζί με επαφές και WhatsApp session)
app.delete('/api/admin/users/:id', adminMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  // Κλείσιμο του WhatsApp client του χρήστη (αν τρέχει)
  const entry = waClients.get(user.id);
  if (entry?.instance) {
    try { entry.instance.destroy(); } catch {}
    waClients.delete(user.id);
  }

  db.prepare('DELETE FROM contacts WHERE user_id = ?').run(user.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
  res.json({ ok: true });
});

// List all users (for admin overview)
app.get('/api/admin/users', adminMiddleware, (req, res) => {
  const users = db.prepare('SELECT id, username, phone, created_at, trial_ends_at, plan, subscription_until, per_use_credits FROM users ORDER BY created_at DESC').all();
  res.json(users.map(u => ({ ...u, access: accessStatus(u) })));
});

// ── Groups API ────────────────────────────────────────────────────────────────
app.get('/api/groups', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT * FROM groups WHERE user_id = ? ORDER BY name').all(req.user.id));
});

app.post('/api/groups', authMiddleware, (req, res) => {
  const name = (req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Δώσε όνομα ομάδας' });
  try {
    const r = db.prepare('INSERT INTO groups (user_id, name) VALUES (?, ?)').run(req.user.id, name);
    res.json({ id: r.lastInsertRowid, name });
  } catch {
    res.status(409).json({ error: 'Η ομάδα υπάρχει ήδη' });
  }
});

app.put('/api/groups/:id', authMiddleware, (req, res) => {
  const name = (req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Δώσε όνομα ομάδας' });
  try {
    db.prepare('UPDATE groups SET name=? WHERE id=? AND user_id=?').run(name, req.params.id, req.user.id);
    res.json({ ok: true });
  } catch {
    res.status(409).json({ error: 'Η ομάδα υπάρχει ήδη' });
  }
});

app.delete('/api/groups/:id', authMiddleware, (req, res) => {
  // Οι επαφές της ομάδας ΔΕΝ διαγράφονται — απλά μένουν χωρίς ομάδα
  db.prepare('UPDATE contacts SET group_id=NULL WHERE group_id=? AND user_id=?').run(req.params.id, req.user.id);
  db.prepare('DELETE FROM groups WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ── Contacts API ──────────────────────────────────────────────────────────────
app.get('/api/contacts', authMiddleware, (req, res) => {
  res.json(db.prepare(`
    SELECT c.*, g.name AS group_name
    FROM contacts c LEFT JOIN groups g ON g.id = c.group_id
    WHERE c.user_id = ? ORDER BY c.name
  `).all(req.user.id));
});

function ownGroupId(userId, groupId) {
  if (!groupId) return null;
  const g = db.prepare('SELECT id FROM groups WHERE id=? AND user_id=?').get(groupId, userId);
  return g ? g.id : null;
}

// Κανονικοποίηση τηλεφώνου: κρατάει μόνο ψηφία, κόβει το διεθνές 00,
// και βάζει 30 σε ελληνικά κινητά 10 ψηφίων (69xxxxxxxx)
function normalizePhone(raw) {
  let d = String(raw || '').replace(/[^0-9]/g, '');
  if (d.startsWith('00')) d = d.slice(2);
  if (d.length === 10 && d.startsWith('69')) d = '30' + d;
  return d;
}

app.post('/api/contacts', authMiddleware, (req, res) => {
  const { name, last_name, phone, salutation, group_id } = req.body;
  if (!name || !phone) return res.status(400).json({ error: 'name and phone required' });
  const digits = normalizePhone(phone);
  const sal = (salutation || '').trim();
  const lname = (last_name || '').trim();
  const gid = ownGroupId(req.user.id, group_id);
  try {
    const r = db.prepare('INSERT INTO contacts (user_id, name, last_name, phone, salutation, group_id) VALUES (?, ?, ?, ?, ?, ?)')
      .run(req.user.id, name, lname, digits, sal, gid);
    res.json({ id: r.lastInsertRowid, name, last_name: lname, phone: digits, salutation: sal, group_id: gid });
  } catch {
    res.status(409).json({ error: 'Ο αριθμός υπάρχει ήδη' });
  }
});

app.put('/api/contacts/:id', authMiddleware, (req, res) => {
  const { name, last_name, phone, salutation, group_id } = req.body;
  const digits = normalizePhone(phone);
  const sal = (salutation || '').trim();
  const lname = (last_name || '').trim();
  const gid = ownGroupId(req.user.id, group_id);
  db.prepare('UPDATE contacts SET name=?, last_name=?, phone=?, salutation=?, group_id=? WHERE id=? AND user_id=?')
    .run(name, lname, digits, sal, gid, req.params.id, req.user.id);
  res.json({ ok: true });
});

// Μαζική εισαγωγή από Excel (το αρχείο διαβάζεται στον browser, εδώ έρχονται γραμμές)
// rows: [{ name, last_name, phone, salutation, group }]
app.post('/api/contacts/import', authMiddleware, (req, res) => {
  const rows = req.body.rows;
  if (!Array.isArray(rows) || rows.length === 0)
    return res.status(400).json({ error: 'Δεν βρέθηκαν γραμμές για εισαγωγή' });
  if (rows.length > 2000)
    return res.status(400).json({ error: 'Μέγιστο 2000 επαφές ανά εισαγωγή' });

  const findGroup = db.prepare('SELECT id FROM groups WHERE user_id=? AND name=?');
  const insGroup  = db.prepare('INSERT INTO groups (user_id, name) VALUES (?, ?)');
  const insContact = db.prepare('INSERT INTO contacts (user_id, name, last_name, phone, salutation, group_id) VALUES (?, ?, ?, ?, ?, ?)');

  let added = 0, skipped = 0, groupsCreated = 0;
  const groupCache = new Map();

  const runImport = db.transaction(() => {
    for (const row of rows) {
      const name = String(row.name || '').trim();
      const lname = String(row.last_name || '').trim();
      const phone = normalizePhone(row.phone);
      const sal = String(row.salutation || '').trim();
      const groupName = String(row.group || '').trim();
      if ((!name && !lname) || phone.length < 10) { skipped++; continue; }

      let gid = null;
      if (groupName) {
        if (groupCache.has(groupName)) {
          gid = groupCache.get(groupName);
        } else {
          const existing = findGroup.get(req.user.id, groupName);
          if (existing) gid = existing.id;
          else { gid = insGroup.run(req.user.id, groupName).lastInsertRowid; groupsCreated++; }
          groupCache.set(groupName, gid);
        }
      }

      try {
        insContact.run(req.user.id, name || lname, name ? lname : '', phone, sal, gid);
        added++;
      } catch {
        skipped++; // διπλό τηλέφωνο
      }
    }
  });
  runImport();

  res.json({ ok: true, added, skipped, groupsCreated });
});

app.delete('/api/contacts/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM contacts WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ── Send API ──────────────────────────────────────────────────────────────────
// Κοινή ρουτίνα αποστολής — χρησιμοποιείται από το /api/send ΚΑΙ τον scheduler
function buildTargets(userId, contactIds) {
  if (contactIds && contactIds.length > 0) {
    return db.prepare(
      `SELECT * FROM contacts WHERE user_id=? AND id IN (${contactIds.map(() => '?').join(',')})`
    ).all(userId, ...contactIds);
  }
  return db.prepare('SELECT * FROM contacts WHERE user_id=?').all(userId);
}

async function runSendJob(userId, message, media, targets) {
  const mediaObj = (media && media.data) ? new MessageMedia(media.mimetype, media.data, media.filename || 'file') : null;
  const mediaName = media ? (media.filename || 'αρχείο') : '';
  const waClient = waClients.get(userId);

  const msgRow = db.prepare('INSERT INTO messages (user_id, body, media_name, total) VALUES (?, ?, ?, ?)')
    .run(userId, message, mediaName, targets.length);
  const messageId = msgRow.lastInsertRowid;

  let ok = 0, fail = 0;
  const recipients = [];
  for (let i = 0; i < targets.length; i++) {
    // Δικλείδα ασφαλείας: αν παράλληλη αποστολή κάλυψε το όριο, σταμάτα εδώ
    if (sentToday(userId) >= DAILY_LIMIT) {
      broadcastTo(userId, { type: 'progress', current: i + 1, total: targets.length, name: 'Ημερήσιο όριο', status: 'fail', error: `Συμπληρώθηκε το όριο των ${DAILY_LIMIT}/μέρα` });
      fail += targets.length - i;
      for (let j = i; j < targets.length; j++) {
        const t = targets[j];
        recipients.push({ name: t.last_name ? `${t.name} ${t.last_name}` : t.name, phone: t.phone, status: 'fail', error: 'daily limit' });
      }
      break;
    }
    const { name, last_name, phone, salutation } = targets[i];
    const fullName = last_name ? `${name} ${last_name}` : name;
    incSent(userId);
    try {
      // Προσωποποίηση: το {όνομα}/{name} γίνεται η προσφώνηση της επαφής.
      // Αν δεν έχει προσφώνηση, το placeholder αφαιρείται καθαρά (μαζί με το κενό πριν).
      const greet = (salutation || '').trim();
      const personalized = greet
        ? message.replace(/\{(όνομα|ονομα|name)\}/giu, greet)
        : message.replace(/[ \t]*\{(όνομα|ονομα|name)\}/giu, '').replace(/ {2,}/g, ' ').trim();
      if (mediaObj) {
        await waClient.instance.sendMessage(`${phone}@c.us`, mediaObj, { caption: personalized });
      } else {
        await waClient.instance.sendMessage(`${phone}@c.us`, personalized);
      }
      ok++;
      recipients.push({ name: fullName, phone, status: 'ok' });
      broadcastTo(userId, { type: 'progress', current: i + 1, total: targets.length, name: fullName, status: 'ok' });
    } catch (err) {
      fail++;
      recipients.push({ name: fullName, phone, status: 'fail', error: err.message });
      broadcastTo(userId, { type: 'progress', current: i + 1, total: targets.length, name: fullName, status: 'fail', error: err.message });
    }
    // Anti-ban: τυχαία καθυστέρηση 5-60 δευτερόλεπτα — μιμείται ανθρώπινο ρυθμό
    if (i < targets.length - 1) {
      const delay = 5000 + Math.floor(Math.random() * 55000);
      broadcastTo(userId, { type: 'waiting', seconds: Math.round(delay / 1000) });
      await sleep(delay);
    }
  }
  db.prepare('UPDATE messages SET ok=?, fail=?, recipients=? WHERE id=?')
    .run(ok, fail, JSON.stringify(recipients), messageId);
  broadcastTo(userId, { type: 'done', ok, fail });
}

app.post('/api/send', authMiddleware, async (req, res) => {
  const { message = '', contactIds, media } = req.body;
  if (!message && !media) return res.status(400).json({ error: 'Γράψε μήνυμα ή επισύναψε αρχείο' });
  if (media && (!media.data || !media.mimetype))
    return res.status(400).json({ error: 'invalid media' });

  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  const status = accessStatus(user);
  if (!status.ok) return res.status(402).json({ error: 'payment_required', access: status });

  const waClient = waClients.get(req.user.id);
  if (!waClient?.ready) return res.status(503).json({ error: 'WhatsApp not connected' });

  const targets = buildTargets(req.user.id, contactIds);

  // Έλεγχος ημερήσιου ορίου (anti-ban)
  const usedToday = sentToday(req.user.id);
  const remaining = DAILY_LIMIT - usedToday;
  if (remaining <= 0)
    return res.status(429).json({ error: `Έφτασες το ημερήσιο όριο των ${DAILY_LIMIT} μηνυμάτων. Δοκίμασε ξανά αύριο.` });
  if (targets.length > remaining)
    return res.status(429).json({ error: `Ημερήσιο όριο: ${DAILY_LIMIT} μηνύματα. Σήμερα απομένουν ${remaining} — επίλεξε λιγότερες επαφές.` });

  // Deduct per-use credit before sending
  if (user.plan === 'per_use') {
    db.prepare('UPDATE users SET per_use_credits = per_use_credits - 1 WHERE id=?').run(req.user.id);
  }

  res.json({ ok: true, total: targets.length });
  runSendJob(req.user.id, message, media, targets);
});

// ── Scheduled sends ───────────────────────────────────────────────────────────
// body: { message, contactIds, media, scheduled_at (ISO UTC) }
app.post('/api/schedule', authMiddleware, (req, res) => {
  const { message = '', contactIds, media, scheduled_at } = req.body;
  if (!message && !media) return res.status(400).json({ error: 'Γράψε μήνυμα ή επισύναψε αρχείο' });
  if (media && (!media.data || !media.mimetype)) return res.status(400).json({ error: 'invalid media' });

  const when = new Date(scheduled_at);
  if (isNaN(when)) return res.status(400).json({ error: 'Μη έγκυρη ημερομηνία' });
  if (when.getTime() < Date.now() + 60 * 1000)
    return res.status(400).json({ error: 'Η ώρα αποστολής πρέπει να είναι τουλάχιστον 1 λεπτό στο μέλλον' });

  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  const status = accessStatus(user);
  if (!status.ok) return res.status(402).json({ error: 'payment_required', access: status });

  const r = db.prepare(`
    INSERT INTO scheduled (user_id, body, media_name, media_mimetype, media_data, contact_ids, scheduled_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    req.user.id,
    message,
    media ? (media.filename || 'αρχείο') : '',
    media ? media.mimetype : '',
    media ? media.data : '',
    JSON.stringify(contactIds || []),
    when.toISOString()
  );
  res.json({ ok: true, id: r.lastInsertRowid });
});

app.get('/api/schedule', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT id, body, media_name, contact_ids, scheduled_at, status, error
    FROM scheduled WHERE user_id=? AND (status='pending' OR datetime(created_at) > datetime('now','-2 days'))
    ORDER BY scheduled_at ASC LIMIT 50
  `).all(req.user.id);
  res.json(rows.map(r => ({ ...r, contact_ids: JSON.parse(r.contact_ids) })));
});

app.delete('/api/schedule/:id', authMiddleware, (req, res) => {
  const r = db.prepare("UPDATE scheduled SET status='cancelled' WHERE id=? AND user_id=? AND status='pending'")
    .run(req.params.id, req.user.id);
  if (r.changes === 0) return res.status(404).json({ error: 'Δεν βρέθηκε ή έχει ήδη σταλεί' });
  res.json({ ok: true });
});

// Scheduler: κάθε 30 δευτερόλεπτα κοιτάει για προγραμματισμένες αποστολές που ήρθε η ώρα τους
async function schedulerTick() {
  const due = db.prepare(`
    SELECT * FROM scheduled WHERE status='pending' AND datetime(scheduled_at) <= datetime('now')
  `).all();

  for (const job of due) {
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(job.user_id);
    if (!user) {
      db.prepare("UPDATE scheduled SET status='failed', error='user not found' WHERE id=?").run(job.id);
      continue;
    }

    // Αν λείπει η συνδρομή τη στιγμή της εκτέλεσης → αποτυχία
    const status = accessStatus(user);
    if (!status.ok) {
      db.prepare("UPDATE scheduled SET status='failed', error='Η συνδρομή έχει λήξει' WHERE id=?").run(job.id);
      continue;
    }

    // Αν το WhatsApp δεν είναι συνδεδεμένο: περιμένουμε (ξαναδοκιμή στο επόμενο tick),
    // αλλά μετά από 24 ώρες καθυστέρησης το μαρκάρουμε αποτυχημένο
    const waClient = waClients.get(job.user_id);
    if (!waClient?.ready) {
      const overdueMs = Date.now() - new Date(job.scheduled_at).getTime();
      if (overdueMs > 24 * 3600 * 1000) {
        db.prepare("UPDATE scheduled SET status='failed', error='Το WhatsApp ήταν αποσυνδεδεμένο' WHERE id=?").run(job.id);
      }
      continue;
    }

    const contactIds = JSON.parse(job.contact_ids);
    const targets = buildTargets(job.user_id, contactIds);
    if (targets.length === 0) {
      db.prepare("UPDATE scheduled SET status='failed', error='Δεν βρέθηκαν επαφές' WHERE id=?").run(job.id);
      continue;
    }

    // Ημερήσιο όριο τη στιγμή της εκτέλεσης
    const remaining = DAILY_LIMIT - sentToday(job.user_id);
    if (targets.length > remaining) {
      db.prepare("UPDATE scheduled SET status='failed', error=? WHERE id=?")
        .run(`Ξεπερνά το ημερήσιο όριο (απέμεναν ${remaining})`, job.id);
      continue;
    }

    if (user.plan === 'per_use') {
      db.prepare('UPDATE users SET per_use_credits = per_use_credits - 1 WHERE id=?').run(job.user_id);
    }

    db.prepare("UPDATE scheduled SET status='sent' WHERE id=?").run(job.id);
    const media = job.media_data ? { mimetype: job.media_mimetype, data: job.media_data, filename: job.media_name } : null;
    broadcastTo(job.user_id, { type: 'scheduled_started', id: job.id });
    runSendJob(job.user_id, job.body, media, targets);
  }
}
setInterval(schedulerTick, 30 * 1000);

// ── History API ───────────────────────────────────────────────────────────────
app.get('/api/history', authMiddleware, (req, res) => {
  const rows = db.prepare(
    'SELECT id, body, media_name, sent_at, total, ok, fail, recipients FROM messages WHERE user_id=? ORDER BY id DESC LIMIT 100'
  ).all(req.user.id);
  res.json(rows.map(r => ({ ...r, recipients: JSON.parse(r.recipients) })));
});

// ── WhatsApp client manager ───────────────────────────────────────────────────
const waClients = new Map();

// Καθάρισμα ορφανών Chromium locks από προηγούμενο container.
// Όταν το container σταματά απότομα, μένουν SingletonLock αρχεία στο volume
// και ο Chromium αρνείται να ξεκινήσει ("profile in use by another computer").
function cleanChromiumLocks() {
  const authDir = '/app/data/.wwebjs_auth';
  if (!fs.existsSync(authDir)) return;
  for (const session of fs.readdirSync(authDir)) {
    for (const lock of ['SingletonLock', 'SingletonCookie', 'SingletonSocket']) {
      try { fs.rmSync(path.join(authDir, session, lock), { force: true }); } catch {}
    }
  }
  console.log('[WA] Chromium locks cleaned');
}
cleanChromiumLocks();

function getOrCreateWaClient(userId) {
  if (waClients.has(userId)) return waClients.get(userId);
  const entry = { instance: null, ready: false };
  waClients.set(userId, entry);

  const client = new Client({
    authStrategy: new LocalAuth({ clientId: `user_${userId}`, dataPath: '/app/data/.wwebjs_auth' }),
    puppeteer: {
      args: [
        '--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
        '--no-zygote', '--disable-extensions', '--disable-default-apps', '--no-first-run',
      ],
      headless: true,
      protocolTimeout: 300000, // 5 λεπτά περιθώριο για αργά/φορτωμένα μηχανήματα
    },
  });

  // Ασφαλής εκκίνηση: αν ο Chromium αποτύχει (π.χ. λόγω φόρτου), ΔΕΝ κρασάρει ο server —
  // καταγράφεται το σφάλμα και ξαναπροσπαθεί σε 30 δευτερόλεπτα.
  function safeInit() {
    client.initialize().catch(err => {
      console.error(`[WA] init failed for user ${userId}: ${err.message} — retry in 30s`);
      try { client.destroy().catch(() => {}); } catch {}
      setTimeout(safeInit, 30000);
    });
  }

  client.on('qr', async qr => {
    entry.ready = false;
    const dataUrl = await QRCode.toDataURL(qr, { width: 280 });
    broadcastTo(userId, { type: 'qr', dataUrl });
  });
  client.on('ready', () => {
    entry.ready = true;
    broadcastTo(userId, { type: 'status', connected: true });
  });
  client.on('disconnected', () => {
    entry.ready = false;
    broadcastTo(userId, { type: 'status', connected: false });
    setTimeout(safeInit, 4000);
  });

  safeInit();
  entry.instance = client;
  return entry;
}

// Δίχτυ ασφαλείας: απρόσμενα σφάλματα από τον Chromium/puppeteer δεν ρίχνουν τον server
process.on('unhandledRejection', err => {
  console.error('[SAFETY] Unhandled rejection:', err?.message || err);
});

// Στην εκκίνηση, άνοιγμα WhatsApp client ΜΟΝΟ για χρήστες με ενεργή πρόσβαση
// (εξοικονόμηση RAM — κάθε client τρέχει δικό του Chromium ~200-300MB)
const allUsers = db.prepare('SELECT * FROM users').all();
allUsers.forEach(u => {
  if (accessStatus(u).ok) getOrCreateWaClient(u.id);
});
console.log(`[WA] Initialized clients for ${allUsers.filter(u => accessStatus(u).ok).length}/${allUsers.length} active users`);

app.post('/api/wa/connect', authMiddleware, (req, res) => {
  getOrCreateWaClient(req.user.id);
  res.json({ ok: true });
});

// Επαφές από τον τηλεφωνικό κατάλογο του συνδεδεμένου WhatsApp
app.get('/api/wa/contacts', authMiddleware, async (req, res) => {
  const entry = waClients.get(req.user.id);
  if (!entry?.ready) return res.status(503).json({ error: 'WhatsApp not connected' });
  try {
    const all = await entry.instance.getContacts();
    const list = all
      .filter(c => c.isMyContact && !c.isGroup && c.id && c.id.server === 'c.us' && c.number)
      .map(c => ({ name: c.name || c.pushname || c.number, phone: c.number }))
      .sort((a, b) => a.name.localeCompare(b.name, 'el'));
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── WebSocket ─────────────────────────────────────────────────────────────────
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const userSockets = new Map();

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const token = url.searchParams.get('token');
  let userId;
  try { userId = jwt.verify(token, JWT_SECRET).id; }
  catch { ws.close(1008, 'Unauthorized'); return; }

  if (!userSockets.has(userId)) userSockets.set(userId, new Set());
  userSockets.get(userId).add(ws);

  const entry = waClients.get(userId);
  ws.send(JSON.stringify({ type: 'status', connected: entry?.ready || false }));
  ws.on('close', () => userSockets.get(userId)?.delete(ws));
});

function broadcastTo(userId, data) {
  const msg = JSON.stringify(data);
  userSockets.get(userId)?.forEach(ws => ws.readyState === WebSocket.OPEN && ws.send(msg));
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Daily database backup ─────────────────────────────────────────────────────
// Κρατάει τα τελευταία 14 ημερήσια αντίγραφα στο /app/data/backups
const BACKUP_DIR = '/app/data/backups';
async function backupDb() {
  try {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const stamp = new Date().toISOString().slice(0, 10);
    await db.backup(path.join(BACKUP_DIR, `contacts-${stamp}.db`));
    const files = fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith('contacts-') && f.endsWith('.db')).sort();
    while (files.length > 14) fs.rmSync(path.join(BACKUP_DIR, files.shift()), { force: true });
    console.log(`[BACKUP] OK -> contacts-${stamp}.db`);
  } catch (e) {
    console.error('[BACKUP] failed:', e.message);
  }
}
backupDb();
setInterval(backupDb, 24 * 3600 * 1000);

server.listen(3000, () => console.log('[HTTP] Listening on :3000'));