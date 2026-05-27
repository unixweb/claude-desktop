const express = require('express');
const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');

const {
  createLink,
  findLinkById,
  listLinksByUser,
  deleteLink,
  slugExists,
  getLinkStats,
} = require('./links');
const { randomSlug, isValidCustomSlug } = require('./slug');

const router = express.Router();

function requireAuth(req, res, next) {
  if (!req.session.user) {
    req.flash('error', 'Bitte zuerst anmelden.');
    return res.redirect('/login');
  }
  next();
}

function appUrl(req) {
  return (
    process.env.APP_URL ||
    `${req.headers['x-forwarded-proto'] || req.protocol}://${req.headers.host}`
  );
}

function isValidUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

async function pickSlug(custom) {
  if (custom) {
    if (!isValidCustomSlug(custom)) {
      return { error: 'Ungültiger Slug. Erlaubt: 3–32 Zeichen, a-z, 0-9, _ oder -.' };
    }
    if (await slugExists(custom)) {
      return { error: 'Dieser Slug ist bereits vergeben.' };
    }
    return { slug: custom };
  }
  for (let i = 0; i < 5; i++) {
    const candidate = randomSlug(6);
    if (!(await slugExists(candidate))) return { slug: candidate };
  }
  return { slug: randomSlug(10) };
}

router.get('/', requireAuth, async (req, res, next) => {
  try {
    const links = await listLinksByUser(req.session.user.id);
    res.render('links', { links, base: appUrl(req) });
  } catch (err) {
    next(err);
  }
});

router.get('/new', requireAuth, (req, res) => {
  res.render('link-new', { values: {} });
});

router.post('/', requireAuth, async (req, res, next) => {
  try {
    const targetUrl = (req.body.targetUrl || '').trim();
    const customSlug = (req.body.slug || '').trim();
    const password = (req.body.password || '').trim();
    const expiresAt = (req.body.expiresAt || '').trim();

    const values = { targetUrl, slug: customSlug, expiresAt };

    if (!isValidUrl(targetUrl)) {
      req.flash('error', 'Bitte eine gültige URL eingeben (http oder https).');
      return res.render('link-new', { values });
    }

    const expires = expiresAt ? new Date(expiresAt) : null;
    if (expiresAt && (isNaN(expires) || expires < new Date())) {
      req.flash('error', 'Ablaufdatum muss in der Zukunft liegen.');
      return res.render('link-new', { values });
    }

    const picked = await pickSlug(customSlug);
    if (picked.error) {
      req.flash('error', picked.error);
      return res.render('link-new', { values });
    }

    const passwordHash = password ? await bcrypt.hash(password, 10) : null;

    const link = await createLink({
      userId: req.session.user.id,
      slug: picked.slug,
      targetUrl,
      passwordHash,
      expiresAt: expires ? expires.toISOString() : null,
    });

    req.flash('success', `Link erstellt: ${appUrl(req)}/s/${link.slug}`);
    res.redirect(`/links/${link.id}`);
  } catch (err) {
    next(err);
  }
});

router.get('/:id', requireAuth, async (req, res, next) => {
  try {
    const link = await findLinkById(Number(req.params.id), req.session.user.id);
    if (!link) return res.redirect('/links');
    const stats = await getLinkStats(link.id);
    res.render('link-detail', { link, stats, base: appUrl(req) });
  } catch (err) {
    next(err);
  }
});

router.post('/:id/delete', requireAuth, async (req, res, next) => {
  try {
    await deleteLink(Number(req.params.id), req.session.user.id);
    req.flash('success', 'Link gelöscht.');
    res.redirect('/links');
  } catch (err) {
    next(err);
  }
});

router.get('/:id/qr', requireAuth, async (req, res, next) => {
  try {
    const link = await findLinkById(Number(req.params.id), req.session.user.id);
    if (!link) return res.status(404).send('Not found');
    const url = `${appUrl(req)}/s/${link.slug}`;
    const png = await QRCode.toBuffer(url, { width: 512, margin: 2 });
    res.set('Content-Type', 'image/png');
    res.set('Content-Disposition', `inline; filename="${link.slug}.png"`);
    res.send(png);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
