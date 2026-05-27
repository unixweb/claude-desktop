const { sql, ensureSchema } = require('./db');

async function createLink({ userId, slug, targetUrl, passwordHash, expiresAt }) {
  await ensureSchema();
  const { rows } = await sql`
    INSERT INTO links (user_id, slug, target_url, password_hash, expires_at)
    VALUES (${userId}, ${slug}, ${targetUrl}, ${passwordHash}, ${expiresAt})
    RETURNING *
  `;
  return rows[0];
}

async function findLinkBySlug(slug) {
  await ensureSchema();
  const { rows } = await sql`SELECT * FROM links WHERE slug = ${slug} LIMIT 1`;
  return rows[0] || null;
}

async function findLinkById(id, userId) {
  const { rows } = await sql`
    SELECT * FROM links WHERE id = ${id} AND user_id = ${userId} LIMIT 1
  `;
  return rows[0] || null;
}

async function listLinksByUser(userId) {
  await ensureSchema();
  const { rows } = await sql`
    SELECT
      l.*,
      COALESCE(c.total, 0)::int AS click_count,
      c.last_clicked
    FROM links l
    LEFT JOIN (
      SELECT link_id, COUNT(*) AS total, MAX(clicked_at) AS last_clicked
      FROM clicks GROUP BY link_id
    ) c ON c.link_id = l.id
    WHERE l.user_id = ${userId}
    ORDER BY l.created_at DESC
  `;
  return rows;
}

async function deleteLink(id, userId) {
  const { rowCount } = await sql`
    DELETE FROM links WHERE id = ${id} AND user_id = ${userId}
  `;
  return rowCount > 0;
}

async function slugExists(slug) {
  const { rows } = await sql`SELECT 1 FROM links WHERE slug = ${slug} LIMIT 1`;
  return rows.length > 0;
}

async function recordClick({ linkId, referrer, country, userAgent }) {
  await sql`
    INSERT INTO clicks (link_id, referrer, country, user_agent)
    VALUES (${linkId}, ${referrer}, ${country}, ${userAgent})
  `;
}

async function getLinkStats(linkId) {
  const { rows: totals } = await sql`
    SELECT COUNT(*)::int AS total FROM clicks WHERE link_id = ${linkId}
  `;
  const { rows: perDay } = await sql`
    SELECT date_trunc('day', clicked_at)::date AS day, COUNT(*)::int AS count
    FROM clicks
    WHERE link_id = ${linkId} AND clicked_at >= NOW() - INTERVAL '30 days'
    GROUP BY day
    ORDER BY day ASC
  `;
  const { rows: byCountry } = await sql`
    SELECT COALESCE(country, '–') AS country, COUNT(*)::int AS count
    FROM clicks
    WHERE link_id = ${linkId}
    GROUP BY country
    ORDER BY count DESC
    LIMIT 10
  `;
  const { rows: byReferrer } = await sql`
    SELECT COALESCE(NULLIF(referrer, ''), 'direct') AS referrer, COUNT(*)::int AS count
    FROM clicks
    WHERE link_id = ${linkId}
    GROUP BY referrer
    ORDER BY count DESC
    LIMIT 5
  `;
  return {
    total: totals[0]?.total || 0,
    perDay,
    byCountry,
    byReferrer,
  };
}

module.exports = {
  createLink,
  findLinkBySlug,
  findLinkById,
  listLinksByUser,
  deleteLink,
  slugExists,
  recordClick,
  getLinkStats,
};
