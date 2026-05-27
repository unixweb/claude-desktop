const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');

const {
  findUserByEmail,
  createUser,
  updateUserPassword,
  createResetToken,
  findResetToken,
  markResetTokenUsed,
} = require('./db');
const { sendPasswordResetMail, sendWelcomeMail } = require('./mailer');
const { findLinkBySlug, recordClick } = require('./links');
const linksRoutes = require('./routes-links');
const tokensRoutes = require('./routes-tokens');
const apiRoutes = require('./routes-api');

const app = express();
app.set('trust proxy', 1);

const VIEWS_DIR = path.join(process.cwd(), 'views');
const PUBLIC_DIR = path.join(process.cwd(), 'public');

app.set('view engine', 'ejs');
app.set('views', VIEWS_DIR);
app.use(express.urlencoded({ extended: false }));
app.use(express.static(PUBLIC_DIR));

app.use(
  cookieSession({
    name: 'sid',
    keys: [process.env.SESSION_SECRET || 'dev-secret-change-me'],
    maxAge: 1000 * 60 * 60 * 24 * 7,
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  })
);

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.success = (req.session.flash && req.session.flash.success) || '';
  res.locals.error = (req.session.flash && req.session.flash.error) || '';
  if (req.session.flash) req.session.flash = null;
  req.flash = (type, msg) => {
    req.session.flash = req.session.flash || {};
    req.session.flash[type] = msg;
  };
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

function appUrl(req) {
  return (
    process.env.APP_URL ||
    `${req.headers['x-forwarded-proto'] || req.protocol}://${req.headers.host}`
  );
}

app.get('/', (req, res) => {
  res.render('landing');
});

app.get('/impressum', (req, res) => res.render('impressum'));
app.get('/datenschutz', (req, res) => res.render('datenschutz'));

app.get('/register', (req, res) => res.render('register'));

app.post('/register', async (req, res, next) => {
  try {
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

    if (await findUserByEmail(email)) {
      req.flash('error', 'Diese E-Mail-Adresse ist bereits registriert.');
      return res.redirect('/register');
    }

    const hash = await bcrypt.hash(password, 12);
    const user = await createUser(email, hash);

    try {
      await sendWelcomeMail(user.email, appUrl(req));
    } catch (err) {
      console.error('[mail] Welcome-Mail fehlgeschlagen:', err);
    }

    req.session.user = { id: user.id, email: user.email };
    req.flash('success', 'Registrierung erfolgreich – willkommen!');
    res.redirect('/dashboard');
  } catch (err) {
    next(err);
  }
});

app.get('/login', (req, res) => res.render('login'));

app.post('/login', async (req, res, next) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';

    const user = await findUserByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      req.flash('error', 'E-Mail oder Passwort ist falsch.');
      return res.redirect('/login');
    }

    req.session.user = { id: user.id, email: user.email };
    res.redirect('/dashboard');
  } catch (err) {
    next(err);
  }
});

app.post('/logout', (req, res) => {
  req.session = null;
  res.redirect('/login');
});

app.get('/dashboard', requireAuth, (req, res) => res.redirect('/links'));

app.use('/links', linksRoutes);
app.use('/tokens', tokensRoutes);
app.use('/api', apiRoutes);

app.get('/s/:slug', async (req, res, next) => {
  try {
    const link = await findLinkBySlug(req.params.slug);
    if (!link) return res.status(404).render('404');

    if (link.expires_at && new Date(link.expires_at) < new Date()) {
      return res.status(410).render('link-expired');
    }

    if (link.password_hash) {
      return res.render('link-password', { slug: link.slug, error: '' });
    }

    recordClick({
      linkId: link.id,
      referrer: req.headers.referer || req.headers.referrer || '',
      country: req.headers['x-vercel-ip-country'] || null,
      userAgent: req.headers['user-agent'] || '',
    }).catch((err) => console.error('[click] insert failed:', err));

    res.redirect(link.target_url);
  } catch (err) {
    next(err);
  }
});

app.post('/s/:slug', async (req, res, next) => {
  try {
    const link = await findLinkBySlug(req.params.slug);
    if (!link) return res.status(404).render('404');
    if (link.expires_at && new Date(link.expires_at) < new Date()) {
      return res.status(410).render('link-expired');
    }
    if (!link.password_hash) return res.redirect(`/s/${link.slug}`);

    const ok = await bcrypt.compare(req.body.password || '', link.password_hash);
    if (!ok) {
      return res.status(401).render('link-password', { slug: link.slug, error: 'Falsches Passwort.' });
    }

    recordClick({
      linkId: link.id,
      referrer: req.headers.referer || req.headers.referrer || '',
      country: req.headers['x-vercel-ip-country'] || null,
      userAgent: req.headers['user-agent'] || '',
    }).catch((err) => console.error('[click] insert failed:', err));

    res.redirect(link.target_url);
  } catch (err) {
    next(err);
  }
});

app.get('/forgot-password', (req, res) => res.render('forgot-password'));

app.post('/forgot-password', async (req, res, next) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const user = await findUserByEmail(email);

    if (user) {
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
      await createResetToken(user.id, token, expiresAt);

      const resetUrl = `${appUrl(req)}/reset-password/${token}`;
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
  } catch (err) {
    next(err);
  }
});

app.get('/reset-password/:token', async (req, res, next) => {
  try {
    const reset = await findResetToken(req.params.token);
    if (!reset || reset.used || new Date(reset.expires_at) < new Date()) {
      req.flash('error', 'Dieser Link ist ungültig oder abgelaufen.');
      return res.redirect('/forgot-password');
    }
    res.render('reset-password', { token: req.params.token });
  } catch (err) {
    next(err);
  }
});

app.post('/reset-password/:token', async (req, res, next) => {
  try {
    const password = req.body.password || '';
    const passwordConfirm = req.body.passwordConfirm || '';

    const reset = await findResetToken(req.params.token);
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
    await updateUserPassword(reset.user_id, hash);
    await markResetTokenUsed(reset.id);

    req.flash('success', 'Passwort wurde aktualisiert. Du kannst dich jetzt anmelden.');
    res.redirect('/login');
  } catch (err) {
    next(err);
  }
});

app.use((req, res) => {
  res.status(404).render('404');
});

app.use((err, req, res, next) => {
  console.error('[error]', err);
  const showDetails = process.env.NODE_ENV !== 'production' || process.env.DEBUG_ERRORS === '1';
  res
    .status(500)
    .type('text/plain')
    .send(showDetails ? `Internal Server Error\n\n${err.stack || err.message}` : 'Internal Server Error');
});

module.exports = app;
