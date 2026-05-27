const { sql, ensureSchema } = require('./db');

const WINDOW_MS = 60 * 60 * 1000;
const MAX_ATTEMPTS_PER_HOUR = 3;
const MIN_FORM_FILL_MS = 2000;

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  return req.ip || 'unknown';
}

async function recordAttempt(ip) {
  await ensureSchema();
  await sql`INSERT INTO registration_attempts (ip) VALUES (${ip})`;
}

async function countRecentAttempts(ip) {
  await ensureSchema();
  const { rows } = await sql`
    SELECT COUNT(*)::int AS n
    FROM registration_attempts
    WHERE ip = ${ip} AND attempted_at >= NOW() - INTERVAL '1 hour'
  `;
  return rows[0]?.n || 0;
}

async function pruneOldAttempts() {
  try {
    await sql`DELETE FROM registration_attempts WHERE attempted_at < NOW() - INTERVAL '7 days'`;
  } catch (_) {}
}

function failsBotCheck({ honeypot, formTs }) {
  if (honeypot && honeypot.length > 0) return 'honeypot';
  const ts = Number(formTs);
  if (!ts || isNaN(ts)) return 'no_ts';
  if (Date.now() - ts < MIN_FORM_FILL_MS) return 'too_fast';
  if (Date.now() - ts > 6 * 60 * 60 * 1000) return 'too_old';
  return null;
}

module.exports = {
  getClientIp,
  recordAttempt,
  countRecentAttempts,
  pruneOldAttempts,
  failsBotCheck,
  WINDOW_MS,
  MAX_ATTEMPTS_PER_HOUR,
};
