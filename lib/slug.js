const crypto = require('crypto');

const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const RESERVED = new Set([
  'api', 'admin', 'app', 'login', 'logout', 'register', 'dashboard',
  'forgot-password', 'reset-password', 'links', 's', 'tokens', 'style.css',
  'favicon.ico', 'static', 'public', 'health', 'about', 'help',
  'impressum', 'datenschutz', 'agb', 'kontakt', 'abuse', 'terms', 'tos',
]);

function randomSlug(length = 6) {
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) out += ALPHABET[bytes[i] % ALPHABET.length];
  return out;
}

function isValidCustomSlug(slug) {
  if (typeof slug !== 'string') return false;
  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(slug)) return false;
  if (RESERVED.has(slug.toLowerCase())) return false;
  return true;
}

module.exports = { randomSlug, isValidCustomSlug, RESERVED };
