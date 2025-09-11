// security.js
// IP allow-list + Basic Auth with a daily rotating password,
// plus a 9:00 AM (Africa/Cairo) notifier that POSTs the password
// { "password": "<today's password>" } to your n8n webhook.

const CIDRMatcher = require('cidr-matcher');
const { DateTime } = require('luxon');
const cron = require('node-cron');

// ---------- Config (env overrides allowed) ----------
const TZ = process.env.TZ || 'Africa/Cairo';
const BASIC_USER = process.env.BASIC_USER || 'sales';
const PASSWORD_MODE = (process.env.PASSWORD_MODE || 'DAILY').toUpperCase(); // DAILY | STATIC
const SECRET = process.env.SECRET || 'changeme'; // base secret for DAILY mode
const STATIC_PASSWORD = process.env.STATIC_PASSWORD || 'supersecret'; // used only if PASSWORD_MODE=STATIC
const GRACE_YESTERDAY = process.env.GRACE_YESTERDAY === '1'; // allow yesterday's password as grace
const ALLOWLIST_IPS = (process.env.ALLOWLIST_IPS || '192.168.1.9/32') // you can add more via env, comma-separated
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const PASSWORD_NOTIFY_URL =
  process.env.PASSWORD_NOTIFY_URL ||
  'https://ebp.app.n8n.cloud/webhook/793618c9-4276-4367-a3b4-09077142c2ff';

// ---------- Helpers ----------
function parseBasicAuth(header) {
  if (!header || !header.startsWith('Basic ')) return null;
  const raw = Buffer.from(header.slice(6), 'base64').toString();
  const i = raw.indexOf(':');
  if (i === -1) return null;
  return { user: raw.slice(0, i), pass: raw.slice(i + 1) };
}

function todaysPassword(now = DateTime.now().setZone(TZ)) {
  // DAILY format: SECRET-YYYYMMDD (Cairo time)
  return `${SECRET}-${now.toFormat('yyyyLLdd')}`;
}

function expectedPasswordMatches(input) {
  if (PASSWORD_MODE === 'STATIC') return input === STATIC_PASSWORD;
  const now = DateTime.now().setZone(TZ);
  if (input === todaysPassword(now)) return true;
  if (GRACE_YESTERDAY && input === todaysPassword(now.minus({ days: 1 }))) return true;
  return false;
}

function getClientIP(req) {
  const fwd = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.ip;
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

  // Schedule the 9:00 AM (Africa/Cairo) daily password push
  // Cron: min hour day month weekday (0 9 * * *)
  cron.schedule('0 9 * * *', () => sendPasswordToWebhook(), { timezone: TZ });

  // Build CIDR matcher for IP allow-list
  const matcher = ALLOWLIST_IPS.length ? new CIDRMatcher(ALLOWLIST_IPS) : null;

  // Middleware chain: IP check -> Basic Auth
  app.use((req, res, next) => {
    // 1) IP allow-list
    if (matcher) {
      const ip = getClientIP(req);
      if (!matcher.contains(ip)) {
        return res.status(403).send('Forbidden (IP not allowed)');
      }
    }

    // 2) HTTP Basic Auth with rotating password
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
