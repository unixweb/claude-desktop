const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');

const {
  findUserByEmail,
  findUserById,
  createUser,
  updateUserPassword,
  createResetToken,
  findResetToken,
  markResetTokenUsed,
} = require('./db');
const { sendPasswordResetMail, sendVerificationMail, sendAccountExistsMail } = require('./mailer');
const {
  createVerificationToken,
  findVerificationToken,
  consumeVerificationToken,
  markUserVerified,
  countRecentResends,
} = require('./verify');
const { verifyAndConsumeToken, consumeBackupCode } = require('./totp');
const { isLimited, recordFailure, clearFailures, WINDOW_MINUTES } = require('./ratelimit');
const accountRoutes = require('./routes-account');
const { findLinkBySlug, recordClick } = require('./links');
const { promoteIfConfigured, touchLastLogin, isRegistrationEnabled } = require('./admin');
const {
  getClientIp,
  recordAttempt,
  countRecentAttempts,
  pruneOldAttempts,
  failsBotCheck,
  MAX_ATTEMPTS_PER_HOUR,
} = require('./antispam');
const linksRoutes = require('./routes-links');
const tokensRoutes = require('./routes-tokens');
const apiRoutes = require('./routes-api');
const adminRoutes = require('./routes-admin');

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

// Konstanter Hash für unbekannte E-Mails: gleiche Laufzeit wie bei echten Konten.
const DUMMY_HASH = '$2a$12$nKWmev8S7UeoSK934eIOcusZvgwLtRMAfnhvDL9uYbSlv0pMftkyq';

const LOGIN_MAX_PER_EMAIL = 10;
const LOGIN_MAX_PER_IP = 50;
const TOTP_MAX_FAILURES = 5;
const LINK_PW_MAX_FAILURES = 10;

function startSession(req, user) {
  req.session.user = { id: user.id, email: user.email, is_admin: !!user.is_admin };
  req.session.sv = user.session_version || 0;
}

// Cookie-Sessions sind stateless: bei jedem Request gegen die DB prüfen, damit
// Sperren, Löschen, Rechte-Entzug und Passwort-Reset sofort greifen.
app.use(async (req, res, next) => {
  if (!req.session.user) return next();
  try {
    const fresh = await findUserById(req.session.user.id);
    if (!fresh || fresh.suspended_at || (req.session.sv || 0) !== fresh.session_version) {
      req.session = {};
      return next();
    }
    req.session.user.email = fresh.email;
    req.session.user.is_admin = !!fresh.is_admin;
    req.currentUser = fresh;
    next();
  } catch (err) {
    next(err);
  }
});

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
app.get('/agb', (req, res) => res.render('agb'));
app.get('/abuse', (req, res) => res.render('abuse'));

app.get('/register', async (req, res, next) => {
  try {
    const enabled = await isRegistrationEnabled();
    res.render('register', { registrationEnabled: enabled, formTs: Date.now() });
  } catch (err) {
    next(err);
  }
});

app.post('/register', async (req, res, next) => {
  try {
    if (!(await isRegistrationEnabled())) {
      req.flash('error', 'Registrierungen sind aktuell deaktiviert.');
      return res.redirect('/register');
    }

    const ip = getClientIp(req);

    const botReason = failsBotCheck({
      honeypot: req.body.website,
      formTs: req.body._t,
    });
    if (botReason) {
      console.warn('[antispam] blocked', { ip, reason: botReason });
      req.flash('success', 'Registrierung erfolgreich – bitte prüfe dein Postfach.');
      return res.redirect('/login');
    }

    const recent = await countRecentAttempts(ip);
    if (recent >= MAX_ATTEMPTS_PER_HOUR) {
      console.warn('[antispam] rate-limited', { ip, recent });
      req.flash('error', 'Zu viele Registrierungs-Versuche von dieser IP. Bitte versuche es später erneut.');
      return res.redirect('/register');
    }

    await recordAttempt(ip);
    pruneOldAttempts().catch(() => {});

    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';
    const passwordConfirm = req.body.passwordConfirm || '';
    const acceptTerms = req.body.acceptTerms === '1';

    if (!acceptTerms) {
      req.flash('error', 'Du musst die Nutzungsbedingungen und Datenschutzerklärung akzeptieren.');
      return res.redirect('/register');
    }

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

    // Kein Hinweis, ob die Adresse schon existiert – der Inhaber bekommt stattdessen eine Info-Mail.
    if (await findUserByEmail(email)) {
      try {
        await sendAccountExistsMail(email, `${appUrl(req)}/forgot-password`);
      } catch (err) {
        console.error('[mail] Account-exists-Mail fehlgeschlagen:', err);
      }
      return res.redirect(`/verify-pending?email=${encodeURIComponent(email)}`);
    }

    const hash = await bcrypt.hash(password, 12);
    const user = await createUser(email, hash);

    await promoteIfConfigured(user.id, user.email);

    try {
      const token = await createVerificationToken(user.id);
      const verifyUrl = `${appUrl(req)}/verify/${token}`;
      await sendVerificationMail(user.email, verifyUrl);
    } catch (err) {
      console.error('[mail] Verification-Mail fehlgeschlagen:', err);
    }

    res.redirect(`/verify-pending?email=${encodeURIComponent(user.email)}`);
  } catch (err) {
    next(err);
  }
});

app.get('/login', (req, res) => res.render('login'));

app.post('/login', async (req, res, next) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';

    const ip = getClientIp(req);

    if (
      (await isLimited('login-email', email, LOGIN_MAX_PER_EMAIL)) ||
      (await isLimited('login-ip', ip, LOGIN_MAX_PER_IP))
    ) {
      req.flash('error', `Zu viele fehlgeschlagene Anmeldeversuche. Bitte in ${WINDOW_MINUTES} Minuten erneut versuchen.`);
      return res.redirect('/login');
    }

    const user = await findUserByEmail(email);
    const passwordOk = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !passwordOk) {
      await recordFailure('login-email', email);
      await recordFailure('login-ip', ip);
      req.flash('error', 'E-Mail oder Passwort ist falsch.');
      return res.redirect('/login');
    }
    await clearFailures('login-email', email);

    if (user.suspended_at) {
      req.flash('error', 'Dieses Konto ist gesperrt. Bitte kontaktiere den Administrator.');
      return res.redirect('/login');
    }

    if (!user.verified_at) {
      return res.redirect(`/verify-pending?email=${encodeURIComponent(user.email)}&from=login`);
    }

    await promoteIfConfigured(user.id, user.email);
    const freshUser = await findUserByEmail(user.email);

    if (freshUser.totp_enabled_at) {
      req.session.pendingUserId = freshUser.id;
      return res.redirect('/login/2fa');
    }

    await touchLastLogin(freshUser.id);
    startSession(req, freshUser);
    res.redirect('/dashboard');
  } catch (err) {
    next(err);
  }
});

app.post('/logout', (req, res) => {
  req.session = null;
  res.redirect('/login');
});

app.get('/verify-pending', (req, res) => {
  res.render('verify-pending', {
    email: req.query.email || '',
    fromLogin: req.query.from === 'login',
  });
});

app.get('/verify/:token', async (req, res, next) => {
  try {
    const v = await findVerificationToken(req.params.token);
    if (!v || v.used || new Date(v.expires_at) < new Date()) {
      return res.render('verify-result', { ok: false, email: v ? v.email : '' });
    }
    await markUserVerified(v.user_id);
    await consumeVerificationToken(v.id);
    await touchLastLogin(v.user_id);

    const user = await findUserByEmail(v.email);
    if (user.suspended_at) {
      req.flash('error', 'Dieses Konto ist gesperrt. Bitte kontaktiere den Administrator.');
      return res.redirect('/login');
    }
    startSession(req, user);
    req.flash('success', 'E-Mail bestätigt – willkommen!');
    res.redirect('/links');
  } catch (err) {
    next(err);
  }
});

app.post('/resend-verification', async (req, res, next) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const user = await findUserByEmail(email);

    req.flash(
      'success',
      'Falls die E-Mail-Adresse zu einem unverifizierten Konto gehört, wurde eine neue Bestätigungs-Mail versendet.'
    );

    if (user && !user.verified_at) {
      const recent = await countRecentResends(user.id);
      if (recent >= 3) {
        console.warn('[verify] resend rate-limited', user.email);
      } else {
        try {
          const token = await createVerificationToken(user.id);
          await sendVerificationMail(user.email, `${appUrl(req)}/verify/${token}`);
        } catch (err) {
          console.error('[mail] Resend fehlgeschlagen:', err);
        }
      }
    }

    res.redirect(`/verify-pending?email=${encodeURIComponent(email)}`);
  } catch (err) {
    next(err);
  }
});

app.get('/dashboard', requireAuth, (req, res) => res.redirect('/links'));

app.get('/login/2fa', (req, res) => {
  if (!req.session.pendingUserId) return res.redirect('/login');
  res.render('login-2fa');
});

app.post('/login/2fa', async (req, res, next) => {
  try {
    const pendingId = req.session.pendingUserId;
    if (!pendingId) return res.redirect('/login');

    // Limit pro Konto, nicht pro Session – ein neuer Login setzt den Zähler nicht zurück.
    if (await isLimited('2fa', pendingId, TOTP_MAX_FAILURES)) {
      req.session.pendingUserId = null;
      req.flash('error', `Zu viele falsche Codes. Bitte in ${WINDOW_MINUTES} Minuten erneut anmelden.`);
      return res.redirect('/login');
    }

    const code = (req.body.code || '').trim();
    const useBackup = req.body.useBackup === '1';

    const ok = useBackup
      ? await consumeBackupCode(pendingId, code)
      : await verifyAndConsumeToken(pendingId, code);

    if (!ok) {
      await recordFailure('2fa', pendingId);
      req.flash('error', useBackup ? 'Backup-Code ungültig.' : 'Code ungültig oder abgelaufen.');
      return res.redirect('/login/2fa');
    }
    await clearFailures('2fa', pendingId);

    const user = await findUserById(pendingId);
    if (!user || user.suspended_at) {
      req.session.pendingUserId = null;
      return res.redirect('/login');
    }

    await touchLastLogin(user.id);
    req.session.pendingUserId = null;
    startSession(req, user);
    res.redirect('/links');
  } catch (err) {
    next(err);
  }
});

app.use('/links', linksRoutes);
app.use('/tokens', tokensRoutes);
app.use('/account', accountRoutes);
app.use('/admin', adminRoutes);
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

    const limitKey = `${link.id}:${getClientIp(req)}`;
    if (await isLimited('link-pw', limitKey, LINK_PW_MAX_FAILURES)) {
      return res.status(429).render('link-password', {
        slug: link.slug,
        error: `Zu viele Fehlversuche. Bitte in ${WINDOW_MINUTES} Minuten erneut versuchen.`,
      });
    }

    const ok = await bcrypt.compare(req.body.password || '', link.password_hash);
    if (!ok) {
      await recordFailure('link-pw', limitKey);
      return res.status(401).render('link-password', { slug: link.slug, error: 'Falsches Passwort.' });
    }
    await clearFailures('link-pw', limitKey);

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
