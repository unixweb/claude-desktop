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
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ;`;
    await sql`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TIMESTAMPTZ DEFAULT NOW()
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
    await sql`
      CREATE TABLE IF NOT EXISTS links (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        slug TEXT UNIQUE NOT NULL,
        target_url TEXT NOT NULL,
        password_hash TEXT,
        expires_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS clicks (
        id SERIAL PRIMARY KEY,
        link_id INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
        clicked_at TIMESTAMPTZ DEFAULT NOW(),
        referrer TEXT,
        country TEXT,
        user_agent TEXT
      );
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_clicks_link_id ON clicks(link_id);`;
    await sql`CREATE INDEX IF NOT EXISTS idx_clicks_clicked_at ON clicks(clicked_at);`;
    await sql`
      CREATE TABLE IF NOT EXISTS api_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT UNIQUE NOT NULL,
        name TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_used_at TIMESTAMPTZ
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
  sql,
  ensureSchema,
  findUserByEmail,
  createUser,
  updateUserPassword,
  createResetToken,
  findResetToken,
  markResetTokenUsed,
};
