require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const bcrypt = require('bcryptjs');

const db = require('./db');
const { sendPasswordResetMail } = require('./mailer');

const app = express();
const PORT = process.env.PORT || 3000;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 },
  })
);
app.use(flash());

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.success = req.flash('success');
  res.locals.error = req.flash('error');
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.user) {
    req.flash('error', 'Bitte zuerst anmelden.');
    return res.redirect('/login');
  }
  next();
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.get('/', (req, res) => {
  res.redirect(req.session.user ? '/dashboard' : '/login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const password = req.body.password || '';
  const passwordConfirm = req.body.passwordConfirm || '';

  if (!isValidEmail(email)) {
    req.flash('error', 'Bitte gib eine gültige E-Mail-Adresse ein.');
    return res.redirect('/register');
  }
  if (password.length < 8) {
    req.flash('error', 'Passwort muss mindestens 8 Zeichen lang sein.');
    return res.redirect('/register');
  }
  if (password !== passwordConfirm) {
    req.flash('error', 'Die Passwörter stimmen nicht überein.');
    return res.redirect('/register');
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    req.flash('error', 'Diese E-Mail-Adresse ist bereits registriert.');
    return res.redirect('/register');
  }

  const hash = await bcrypt.hash(password, 12);
  const info = db
    .prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)')
    .run(email, hash);

  req.session.user = { id: info.lastInsertRowid, email };
  req.flash('success', 'Registrierung erfolgreich – willkommen!');
  res.redirect('/dashboard');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const password = req.body.password || '';

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    req.flash('error', 'E-Mail oder Passwort ist falsch.');
    return res.redirect('/login');
  }

  req.session.user = { id: user.id, email: user.email };
  res.redirect('/dashboard');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard');
});

app.get('/forgot-password', (req, res) => {
  res.render('forgot-password');
});

app.post('/forgot-password', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();

  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);

  if (user) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    db.prepare(
      'INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)'
    ).run(user.id, token, expiresAt);

    const resetUrl = `${APP_URL}/reset-password/${token}`;
    try {
      await sendPasswordResetMail(email, resetUrl);
    } catch (err) {
      console.error('[mail] Fehler beim Senden:', err);
    }
  }

  req.flash(
    'success',
    'Falls die E-Mail-Adresse registriert ist, wurde eine Nachricht mit weiteren Anweisungen versendet.'
  );
  res.redirect('/login');
});

app.get('/reset-password/:token', (req, res) => {
  const reset = db
    .prepare('SELECT * FROM password_resets WHERE token = ?')
    .get(req.params.token);

  if (!reset || reset.used || new Date(reset.expires_at) < new Date()) {
    req.flash('error', 'Dieser Link ist ungültig oder abgelaufen.');
    return res.redirect('/forgot-password');
  }

  res.render('reset-password', { token: req.params.token });
});

app.post('/reset-password/:token', async (req, res) => {
  const password = req.body.password || '';
  const passwordConfirm = req.body.passwordConfirm || '';

  const reset = db
    .prepare('SELECT * FROM password_resets WHERE token = ?')
    .get(req.params.token);

  if (!reset || reset.used || new Date(reset.expires_at) < new Date()) {
    req.flash('error', 'Dieser Link ist ungültig oder abgelaufen.');
    return res.redirect('/forgot-password');
  }

  if (password.length < 8) {
    req.flash('error', 'Passwort muss mindestens 8 Zeichen lang sein.');
    return res.redirect(`/reset-password/${req.params.token}`);
  }
  if (password !== passwordConfirm) {
    req.flash('error', 'Die Passwörter stimmen nicht überein.');
    return res.redirect(`/reset-password/${req.params.token}`);
  }

  const hash = await bcrypt.hash(password, 12);

  const tx = db.transaction(() => {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, reset.user_id);
    db.prepare('UPDATE password_resets SET used = 1 WHERE id = ?').run(reset.id);
  });
  tx();

  req.flash('success', 'Passwort wurde aktualisiert. Du kannst dich jetzt anmelden.');
  res.redirect('/login');
});

app.use((req, res) => {
  res.status(404).render('404');
});

app.listen(PORT, () => {
  console.log(`Login-App läuft auf ${APP_URL}`);
});
