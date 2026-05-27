const crypto = require('crypto');
const { sql, ensureSchema } = require('./db');

function generateToken() {
  return 'sk_' + crypto.randomBytes(24).toString('base64url');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function createToken(userId, name) {
  await ensureSchema();
  const token = generateToken();
  const hash = hashToken(token);
  const { rows } = await sql`
    INSERT INTO api_tokens (user_id, token_hash, name)
    VALUES (${userId}, ${hash}, ${name || null})
    RETURNING id, name, created_at
  `;
  return { token, record: rows[0] };
}

async function listTokens(userId) {
  await ensureSchema();
  const { rows } = await sql`
    SELECT id, name, created_at, last_used_at
    FROM api_tokens
    WHERE user_id = ${userId}
    ORDER BY created_at DESC
  `;
  return rows;
}

async function deleteToken(id, userId) {
  const { rowCount } = await sql`
    DELETE FROM api_tokens WHERE id = ${id} AND user_id = ${userId}
  `;
  return rowCount > 0;
}

async function findUserByToken(token) {
  if (!token) return null;
  const hash = hashToken(token);
  const { rows } = await sql`
    SELECT t.id AS token_id, t.user_id, u.email
    FROM api_tokens t
    JOIN users u ON u.id = t.user_id
    WHERE t.token_hash = ${hash}
    LIMIT 1
  `;
  if (!rows[0]) return null;
  sql`UPDATE api_tokens SET last_used_at = NOW() WHERE id = ${rows[0].token_id}`.catch(() => {});
  return { id: rows[0].user_id, email: rows[0].email, tokenId: rows[0].token_id };
}

module.exports = { createToken, listTokens, deleteToken, findUserByToken };
