const express = require('express');
const bcrypt = require('bcryptjs');

const { findUserByToken } = require('./tokens');
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
router.use(express.json());

router.use(async (req, res, next) => {
  const header = req.headers.authorization || '';
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (!match) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header. Use: Bearer <token>' });
  }
  try {
    const user = await findUserByToken(match[1]);
    if (!user) return res.status(401).json({ error: 'Invalid API token' });
    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
});

function isValidUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

function appUrl(req) {
  return (
    process.env.APP_URL ||
    `${req.headers['x-forwarded-proto'] || req.protocol}://${req.headers.host}`
  );
}

function serializeLink(link, base) {
  return {
    id: link.id,
    slug: link.slug,
    short_url: `${base}/s/${link.slug}`,
    target_url: link.target_url,
    has_password: !!link.password_hash,
    expires_at: link.expires_at,
    created_at: link.created_at,
    click_count: link.click_count,
    last_clicked: link.last_clicked,
  };
}

router.get('/links', async (req, res, next) => {
  try {
    const links = await listLinksByUser(req.user.id);
    res.json({ links: links.map((l) => serializeLink(l, appUrl(req))) });
  } catch (err) {
    next(err);
  }
});

router.post('/links', async (req, res, next) => {
  try {
    const targetUrl = (req.body.target_url || req.body.targetUrl || '').trim();
    const customSlug = (req.body.slug || '').trim();
    const password = (req.body.password || '').trim();
    const expiresAt = req.body.expires_at || req.body.expiresAt || null;

    if (!isValidUrl(targetUrl)) {
      return res.status(400).json({ error: 'target_url must be a valid http(s) URL' });
    }

    let slug;
    if (customSlug) {
      if (!isValidCustomSlug(customSlug)) {
        return res.status(400).json({ error: 'Invalid slug. Allowed: 3-32 chars [a-zA-Z0-9_-].' });
      }
      if (await slugExists(customSlug)) {
        return res.status(409).json({ error: 'Slug already taken' });
      }
      slug = customSlug;
    } else {
      for (let i = 0; i < 5; i++) {
        const candidate = randomSlug(6);
        if (!(await slugExists(candidate))) { slug = candidate; break; }
      }
      if (!slug) slug = randomSlug(10);
    }

    let expires = null;
    if (expiresAt) {
      const d = new Date(expiresAt);
      if (isNaN(d) || d < new Date()) {
        return res.status(400).json({ error: 'expires_at must be a future date' });
      }
      expires = d.toISOString();
    }

    const passwordHash = password ? await bcrypt.hash(password, 10) : null;

    const link = await createLink({
      userId: req.user.id,
      slug,
      targetUrl,
      passwordHash,
      expiresAt: expires,
    });

    res.status(201).json({ link: serializeLink({ ...link, click_count: 0, last_clicked: null }, appUrl(req)) });
  } catch (err) {
    next(err);
  }
});

router.get('/links/:id', async (req, res, next) => {
  try {
    const link = await findLinkById(Number(req.params.id), req.user.id);
    if (!link) return res.status(404).json({ error: 'Not found' });
    const stats = await getLinkStats(link.id);
    res.json({
      link: serializeLink({ ...link, click_count: stats.total, last_clicked: null }, appUrl(req)),
      stats,
    });
  } catch (err) {
    next(err);
  }
});

router.delete('/links/:id', async (req, res, next) => {
  try {
    const ok = await deleteLink(Number(req.params.id), req.user.id);
    if (!ok) return res.status(404).json({ error: 'Not found' });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

router.use((err, req, res, next) => {
  console.error('[api error]', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

module.exports = router;
