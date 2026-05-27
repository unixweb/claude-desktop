const express = require('express');
const { createToken, listTokens, deleteToken } = require('./tokens');

const router = express.Router();

function requireAuth(req, res, next) {
  if (!req.session.user) {
    req.flash('error', 'Bitte zuerst anmelden.');
    return res.redirect('/login');
  }
  next();
}

router.get('/', requireAuth, async (req, res, next) => {
  try {
    const tokens = await listTokens(req.session.user.id);
    const justCreated = req.session.justCreatedToken || null;
    req.session.justCreatedToken = null;
    res.render('tokens', { tokens, justCreated });
  } catch (err) {
    next(err);
  }
});

router.post('/', requireAuth, async (req, res, next) => {
  try {
    const name = (req.body.name || '').trim().slice(0, 64) || null;
    const { token } = await createToken(req.session.user.id, name);
    req.session.justCreatedToken = token;
    req.flash('success', 'Neuer API-Token erstellt. Bitte jetzt kopieren – wird nur einmal angezeigt!');
    res.redirect('/tokens');
  } catch (err) {
    next(err);
  }
});

router.post('/:id/delete', requireAuth, async (req, res, next) => {
  try {
    await deleteToken(Number(req.params.id), req.session.user.id);
    req.flash('success', 'Token widerrufen.');
    res.redirect('/tokens');
  } catch (err) {
    next(err);
  }
});

module.exports = router;
