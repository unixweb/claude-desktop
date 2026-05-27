const { sql } = require('@vercel/postgres');

let schemaReady = null;

async function ensureSchema() {
  if (schemaReady) return schemaReady;
  schemaReady = (async () => {
    await sql`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS password_resets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        used BOOLEAN DEFAULT FALSE
      );
    `;
  })();
  return schemaReady;
}

async function findUserByEmail(email) {
  await ensureSchema();
  const { rows } = await sql`SELECT * FROM users WHERE email = ${email} LIMIT 1`;
  return rows[0] || null;
}

async function createUser(email, passwordHash) {
  await ensureSchema();
  const { rows } = await sql`
    INSERT INTO users (email, password_hash)
    VALUES (${email}, ${passwordHash})
    RETURNING id, email
  `;
  return rows[0];
}

async function updateUserPassword(userId, passwordHash) {
  await sql`UPDATE users SET password_hash = ${passwordHash} WHERE id = ${userId}`;
}

async function createResetToken(userId, token, expiresAt) {
  await ensureSchema();
  await sql`
    INSERT INTO password_resets (user_id, token, expires_at)
    VALUES (${userId}, ${token}, ${expiresAt})
  `;
}

async function findResetToken(token) {
  await ensureSchema();
  const { rows } = await sql`SELECT * FROM password_resets WHERE token = ${token} LIMIT 1`;
  return rows[0] || null;
}

async function markResetTokenUsed(id) {
  await sql`UPDATE password_resets SET used = TRUE WHERE id = ${id}`;
}

module.exports = {
  ensureSchema,
  findUserByEmail,
  createUser,
  updateUserPassword,
  createResetToken,
  findResetToken,
  markResetTokenUsed,
};
