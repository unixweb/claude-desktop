const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { authenticator } = require('otplib');
const { sql, ensureSchema } = require('./db');

authenticator.options = { window: 1, step: 30 };

const ISSUER = 'mygopage.de';

function generateSecret() {
  return authenticator.generateSecret();
}

function buildOtpAuthUrl(email, secret) {
  return authenticator.keyuri(email, ISSUER, secret);
}

function verifyToken(token, secret) {
  if (!secret || !token) return false;
  try {
    return authenticator.verify({
      token: token.toString().replace(/\s/g, ''),
      secret,
    });
  } catch (_) {
    return false;
  }
}

function generateBackupCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(5).toString('hex').toUpperCase().slice(0, 8);
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4, 8)}`);
  }
  return codes;
}

async function saveBackupCodes(userId, codes) {
  await ensureSchema();
  await sql`DELETE FROM totp_backup_codes WHERE user_id = ${userId}`;
  for (const code of codes) {
    const hash = await bcrypt.hash(code.replace(/-/g, ''), 10);
    await sql`INSERT INTO totp_backup_codes (user_id, code_hash) VALUES (${userId}, ${hash})`;
  }
}

async function consumeBackupCode(userId, code) {
  const norm = (code || '').replace(/[-\s]/g, '').toUpperCase();
  if (!norm) return false;
  const { rows } = await sql`
    SELECT id, code_hash FROM totp_backup_codes
    WHERE user_id = ${userId} AND used_at IS NULL
  `;
  for (const row of rows) {
    if (await bcrypt.compare(norm, row.code_hash)) {
      await sql`UPDATE totp_backup_codes SET used_at = NOW() WHERE id = ${row.id}`;
      return true;
    }
  }
  return false;
}

async function enableTotp(userId, secret) {
  await sql`UPDATE users SET totp_secret = ${secret}, totp_enabled_at = NOW() WHERE id = ${userId}`;
}

async function disableTotp(userId) {
  await sql`UPDATE users SET totp_secret = NULL, totp_enabled_at = NULL WHERE id = ${userId}`;
  await sql`DELETE FROM totp_backup_codes WHERE user_id = ${userId}`;
}

async function getBackupCodeCount(userId) {
  const { rows } = await sql`
    SELECT COUNT(*)::int AS n FROM totp_backup_codes
    WHERE user_id = ${userId} AND used_at IS NULL
  `;
  return rows[0]?.n || 0;
}

async function getUserSecret(userId) {
  const { rows } = await sql`SELECT totp_secret FROM users WHERE id = ${userId} LIMIT 1`;
  return rows[0]?.totp_secret || null;
}

module.exports = {
  generateSecret,
  buildOtpAuthUrl,
  verifyToken,
  generateBackupCodes,
  saveBackupCodes,
  consumeBackupCode,
  enableTotp,
  disableTotp,
  getBackupCodeCount,
  getUserSecret,
};
