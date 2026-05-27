const express = require('express');
const QRCode = require('qrcode');
const { findUserByEmail } = require('./db');
const {
  generateSecret,
  buildOtpAuthUrl,
  verifyToken,
  generateBackupCodes,
  saveBackupCodes,
  enableTotp,
  disableTotp,
  getBackupCodeCount,
} = require('./totp');

const router = express.Router();

function requireAuth(req, res, next) {
  if (!req.session.user) {
    req.flash('error', 'Bitte zuerst anmelden.');
    return res.redirect('/login');
  }
  next();
}

router.use(requireAuth);

router.get('/2fa', async (req, res, next) => {
  try {
    const user = await findUserByEmail(req.session.user.email);
    const codesLeft = user.totp_enabled_at ? await getBackupCodeCount(user.id) : 0;
    res.render('account-2fa', {
      enabled: !!user.totp_enabled_at,
      codesLeft,
    });
  } catch (err) {
    next(err);
  }
});

router.post('/2fa/setup', async (req, res, next) => {
  try {
    const user = await findUserByEmail(req.session.user.email);
    if (user.totp_enabled_at) {
      req.flash('error', '2FA ist bereits aktiviert.');
      return res.redirect('/account/2fa');
    }
    const secret = generateSecret();
    req.session.pendingTotpSecret = secret;
    const otpauth = buildOtpAuthUrl(user.email, secret);
    const qrDataUrl = await QRCode.toDataURL(otpauth, { width: 220, margin: 1 });
    res.render('account-2fa-setup', { secret, qrDataUrl });
  } catch (err) {
    next(err);
  }
});

router.post('/2fa/enable', async (req, res, next) => {
  try {
    const secret = req.session.pendingTotpSecret;
    if (!secret) {
      req.flash('error', 'Setup abgelaufen. Bitte erneut starten.');
      return res.redirect('/account/2fa');
    }
    const code = (req.body.code || '').trim();
    if (!verifyToken(code, secret)) {
      req.flash('error', 'Code ungültig. Bitte erneut versuchen.');
      return res.redirect('/account/2fa');
    }
    const userId = req.session.user.id;
    await enableTotp(userId, secret);
    const codes = generateBackupCodes(10);
    await saveBackupCodes(userId, codes);
    req.session.pendingTotpSecret = null;
    req.session.showBackupCodes = codes;
    res.redirect('/account/2fa/backup-codes');
  } catch (err) {
    next(err);
  }
});

router.get('/2fa/backup-codes', (req, res) => {
  const codes = req.session.showBackupCodes;
  req.session.showBackupCodes = null;
  if (!codes) return res.redirect('/account/2fa');
  res.render('account-2fa-codes', { codes });
});

router.post('/2fa/regenerate-codes', async (req, res, next) => {
  try {
    const userId = req.session.user.id;
    const codes = generateBackupCodes(10);
    await saveBackupCodes(userId, codes);
    req.session.showBackupCodes = codes;
    req.flash('success', 'Neue Backup-Codes erstellt. Die alten sind ungültig.');
    res.redirect('/account/2fa/backup-codes');
  } catch (err) {
    next(err);
  }
});

router.post('/2fa/disable', async (req, res, next) => {
  try {
    await disableTotp(req.session.user.id);
    req.flash('success', '2FA deaktiviert.');
    res.redirect('/account/2fa');
  } catch (err) {
    next(err);
  }
});

module.exports = router;
