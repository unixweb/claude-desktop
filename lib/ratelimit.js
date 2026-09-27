const { sql, ensureSchema } = require('./db');

// Fehlversuchs-Zähler in der DB (serverless-tauglich, kein In-Memory-State).
const WINDOW_MINUTES = 15;

async function isLimited(scope, key, max) {
  await ensureSchema();
  const { rows } = await sql`
    SELECT COUNT(*)::int AS n
    FROM auth_failures
    WHERE scope = ${scope} AND key = ${String(key)}
      AND attempted_at >= NOW() - make_interval(mins => ${WINDOW_MINUTES})
  `;
  return (rows[0]?.n || 0) >= max;
}

async function recordFailure(scope, key) {
  await ensureSchema();
  await sql`INSERT INTO auth_failures (scope, key) VALUES (${scope}, ${String(key)})`;
  sql`DELETE FROM auth_failures WHERE attempted_at < NOW() - INTERVAL '1 day'`.catch(() => {});
}

async function clearFailures(scope, key) {
  await sql`DELETE FROM auth_failures WHERE scope = ${scope} AND key = ${String(key)}`;
}

module.exports = { isLimited, recordFailure, clearFailures, WINDOW_MINUTES };
