// security.js
// IPv4 allow-list (CIDR), Basic Auth with daily rotating password,
// and a 9:00 AM (Africa/Cairo) notifier that POSTs { password } to your n8n webhook.

const { DateTime } = require('luxon');
const cron = require('node-cron');

// ---------- Config via env ----------
const TZ = process.env.TZ || 'Africa/Cairo';
const BASIC_USER = process.env.BASIC_USER || 'sales';
const PASSWORD_MODE = (process.env.PASSWORD_MODE || 'DAILY').toUpperCase(); // DAILY | STATIC
const SECRET = process.env.SECRET || 'changeme';
const STATIC_PASSWORD = process.env.STATIC_PASSWORD || 'supersecret';
const GRACE_YESTERDAY = process.env.GRACE_YESTERDAY === '1';
const ALLOWLIST_IPS = (process.env.ALLOWLIST_IPS || '192.168.1.9/32')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
const PASSWORD_NOTIFY_URL =
  process.env.PASSWORD_NOTIFY_URL ||
  'https://ebp.app.n8n.cloud/webhook/793618c9-4276-4367-a3b4-09077142c2ff';

// ---------- Minimal IPv4 CIDR matcher ----------
function ipv4ToInt(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return (((p[0] << 24) >>> 0) + ((p[1] << 16) >>> 0) + ((p[2] << 8) >>> 0) + (p[3] >>> 0)) >>> 0;
}
function parseCIDR(cidr) {
  // Supports "a.b.c.d/nn" or plain "a.b.c.d" (treated as /32)
  const parts = cidr.split('/');
  const ip = parts[0];
  const bits = parts[1] !== undefined ? parseInt(parts[1], 10) : 32;
  const ipInt = ipv4ToInt(ip);
  if (ipInt == null || !(bits >= 0 && bits <= 32)) return null;
  const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
  const start = (ipInt & mask) >>> 0;
  const end = (start | (~mask >>> 0)) >>> 0;
  return { start, end };
}
function buildRanges(list) {
  return list.map(parseCIDR).filter(Boolean);
}
function ipAllowed(ip, ranges) {
  const ipInt = ipv4ToInt(ip);
  if (ipInt == null) return false; // only IPv4 supported here
  for (const r of ranges) {
    if (ipInt >= r.start && ipInt <= r.end) return true;
  }
  return false;
}

// ---------- Helpers ----------
function parseBasicAuth(header) {
  if (!header || !header.startsWith('Basic ')) return null;
  const raw = Buffer.from(header.slice(6), 'base64').toString();
  const i = raw.indexOf(':');
  if (i === -1) return null;
  return { user: raw.slice(0, i), pass: raw.slice(i + 1) };
}
function getClientIP(req) {
  // trust proxy is enabled; first XFF is original client
  const fwd = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || (req.ip || '').replace('::ffff:', '');
}
function todaysPassword(now = DateTime.now().setZone(TZ)) {
  return `${SECRET}-${now.toFormat('yyyyLLdd')}`;
}
function expectedPasswordMatches(input) {
  if (PASSWORD_MODE === 'STATIC') return input === STATIC_PASSWORD;
  const now = DateTime.now().setZone(TZ);
  if (input === todaysPassword(now)) return true;
  if (GRACE_YESTERDAY && input === todaysPassword(now.minus({ days: 1 }))) return true;
  return false;
}
async function sendPasswordToWebhook() {
  try {
    const pwd = todaysPassword();
    const res = await fetch(PASSWORD_NOTIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pwd })
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      console.error('[security] Password notify failed:', res.status, text.slice(0, 200));
      return;
    }
    console.log('[security] Password sent to webhook at 09:00', TZ);
  } catch (e) {
    console.error('[security] Password notify error:', e && e.message ? e.message : e);
  }
}

// ---------- Main export ----------
module.exports = function secure(app) {
  app.set('trust proxy', 1);

  // Schedule daily 09:00 Cairo notifier
  cron.schedule('0 9 * * *', () => sendPasswordToWebhook(), { timezone: TZ });

  const ranges = buildRanges(ALLOWLIST_IPS);

  app.use((req, res, next) => {
    // 1) IP allow-list (IPv4 only)
    const ip = getClientIP(req);
    if (!ipAllowed(ip, ranges)) {
      return res.status(403).send('Forbidden (IP not allowed)');
    }

    // 2) Basic Auth
    const creds = parseBasicAuth(req.headers.authorization);
    const challenge = () => {
      res.set('WWW-Authenticate', 'Basic realm="SERP Viewer"');
      return res.status(401).send('Authentication required');
    };
    if (!creds) return challenge();
    if (creds.user !== BASIC_USER) return challenge();
    if (!expectedPasswordMatches(creds.pass)) return challenge();

    return next();
  });
};
