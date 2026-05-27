const { sql, ensureSchema } = require('./db');

function adminEmails() {
  return (process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
}

function isAdminEmail(email) {
  return adminEmails().includes((email || '').toLowerCase());
}

async function promoteIfConfigured(userId, email) {
  if (!isAdminEmail(email)) return;
  await sql`UPDATE users SET is_admin = TRUE WHERE id = ${userId} AND is_admin = FALSE`;
}

async function touchLastLogin(userId) {
  await sql`UPDATE users SET last_login_at = NOW() WHERE id = ${userId}`;
}

async function listUsersWithStats() {
  await ensureSchema();
  const { rows } = await sql`
    SELECT
      u.id, u.email, u.is_admin, u.suspended_at, u.verified_at, u.totp_enabled_at, u.created_at, u.last_login_at,
      COALESCE(l.cnt, 0)::int AS link_count,
      COALESCE(c.cnt, 0)::int AS click_count
    FROM users u
    LEFT JOIN (SELECT user_id, COUNT(*) AS cnt FROM links GROUP BY user_id) l ON l.user_id = u.id
    LEFT JOIN (
      SELECT l.user_id, COUNT(c.id) AS cnt
      FROM links l LEFT JOIN clicks c ON c.link_id = l.id
      GROUP BY l.user_id
    ) c ON c.user_id = u.id
    ORDER BY u.created_at DESC
  `;
  return rows;
}

async function getTotals() {
  const { rows } = await sql`
    SELECT
      (SELECT COUNT(*)::int FROM users) AS users,
      (SELECT COUNT(*)::int FROM users WHERE is_admin) AS admins,
      (SELECT COUNT(*)::int FROM users WHERE suspended_at IS NOT NULL) AS suspended,
      (SELECT COUNT(*)::int FROM links) AS links,
      (SELECT COUNT(*)::int FROM clicks) AS clicks
  `;
  return rows[0];
}

async function setAdmin(userId, value) {
  await sql`UPDATE users SET is_admin = ${value} WHERE id = ${userId}`;
}

async function setSuspended(userId, value) {
  if (value) {
    await sql`UPDATE users SET suspended_at = NOW() WHERE id = ${userId}`;
  } else {
    await sql`UPDATE users SET suspended_at = NULL WHERE id = ${userId}`;
  }
}

async function deleteUserById(userId) {
  await sql`DELETE FROM users WHERE id = ${userId}`;
}

async function getSetting(key, fallback = null) {
  await ensureSchema();
  const { rows } = await sql`SELECT value FROM settings WHERE key = ${key} LIMIT 1`;
  return rows[0]?.value ?? fallback;
}

async function setSetting(key, value) {
  await ensureSchema();
  await sql`
    INSERT INTO settings (key, value, updated_at)
    VALUES (${key}, ${value}, NOW())
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
  `;
}

async function isRegistrationEnabled() {
  const v = await getSetting('registration_enabled', 'true');
  return v !== 'false';
}

async function setRegistrationEnabled(enabled) {
  await setSetting('registration_enabled', enabled ? 'true' : 'false');
}

module.exports = {
  isAdminEmail,
  promoteIfConfigured,
  touchLastLogin,
  listUsersWithStats,
  getTotals,
  setAdmin,
  setSuspended,
  deleteUserById,
  isRegistrationEnabled,
  setRegistrationEnabled,
};
