const crypto = require('crypto');
const { sql, ensureSchema } = require('./db');

const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

async function createVerificationToken(userId) {
  await ensureSchema();
  const token = generateToken();
  const expiresAt = new Date(Date.now() + TOKEN_TTL_MS).toISOString();
  await sql`
    INSERT INTO email_verifications (user_id, token, expires_at)
    VALUES (${userId}, ${token}, ${expiresAt})
  `;
  return token;
}

async function findVerificationToken(token) {
  await ensureSchema();
  const { rows } = await sql`
    SELECT v.*, u.email
    FROM email_verifications v
    JOIN users u ON u.id = v.user_id
    WHERE v.token = ${token}
    LIMIT 1
  `;
  return rows[0] || null;
}

async function consumeVerificationToken(id) {
  await sql`UPDATE email_verifications SET used = TRUE WHERE id = ${id}`;
}

async function markUserVerified(userId) {
  await sql`UPDATE users SET verified_at = NOW() WHERE id = ${userId} AND verified_at IS NULL`;
}

async function countRecentResends(userId) {
  const { rows } = await sql`
    SELECT COUNT(*)::int AS n
    FROM email_verifications
    WHERE user_id = ${userId} AND created_at >= NOW() - INTERVAL '1 hour'
  `;
  return rows[0]?.n || 0;
}

module.exports = {
  createVerificationToken,
  findVerificationToken,
  consumeVerificationToken,
  markUserVerified,
  countRecentResends,
};
