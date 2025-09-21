/* server.js — static server with CSP that allows direct fetch to your webhook,
   security middleware is loadable but can be bypassed in dev via AUTH_DISABLED=1
*/
const path = require('path');
const express = require('express');
const compression = require('compression');
const morgan = require('morgan');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const AUTH_DISABLED = process.env.AUTH_DISABLED === '1';

// honor proxies on Railway/Heroku so IP + HTTPS info is correct if security uses it
app.set('trust proxy', process.env.TRUST_PROXY ? Number(process.env.TRUST_PROXY) : 1);

// Allow direct outbound fetch from the browser to your data webhook (for the dashboard button).
// Multiple values comma-separated; "*" works too.
const CONNECT_SRC = (process.env.CONNECT_SRC || 'https://primary-production-9e01d.up.railway.app')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// Try to load security module, but allow bypass via AUTH_DISABLED or missing file
let secure = null;
try {
  secure = require('./security');
} catch (err) {
  console.warn('[server] security module not found, continuing without it.');
}

// Apply security first (unless disabled)
if (AUTH_DISABLED) {
  console.warn('[server] AUTH_DISABLED=1 — security middleware is bypassed for this process.');
} else if (typeof secure === 'function') {
  secure(app);
} else if (secure && typeof secure.default === 'function') {
  secure.default(app);
} else {
  console.warn('[server] security middleware not applied (module missing or invalid export).');
}

// Standard hardening; CSP permits inline script/style in your current HTML.
// You can disable CSP entirely with NO_CSP=1 if you need quick debugging.
if (process.env.NO_CSP === '1') {
  app.use(
    helmet({
      contentSecurityPolicy: false,
      referrerPolicy: { policy: 'no-referrer' },
      crossOriginEmbedderPolicy: false
    })
  );
} else {
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          "default-src": ["'self'"],
          "script-src": ["'self'", "'unsafe-inline'", "https:"],
          "style-src": ["'self'", "'unsafe-inline'", "https:"],
          "img-src": ["'self'", "data:", "https:"],
          "connect-src": ["'self'", ...CONNECT_SRC], // allow direct fetch to webhook(s)
          "frame-ancestors": ["'none'"],
          "object-src": ["'none'"],
          "base-uri": ["'self'"]
        }
      },
      referrerPolicy: { policy: 'no-referrer' },
      crossOriginEmbedderPolicy: false
    })
  );
}

app.use(compression());
app.use(morgan(NODE_ENV === 'production' ? 'tiny' : 'dev'));
app.use(express.json({ limit: '1mb' }));

// Static hosting
const STATIC_DIR = path.join(__dirname, 'public');
app.use(
  express.static(STATIC_DIR, {
    etag: true,
    lastModified: true,
    maxAge: '1h',
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('index.html')) {
        res.setHeader('Cache-Control', 'no-store');
      }
    }
  })
);

// Health
app.get(['/health', '/healthz', '/_health'], (_req, res) => res.json({ ok: true }));

// SPA fallback
app.get('*', (_req, res) => {
  res.sendFile(path.join(STATIC_DIR, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Static app running on http://0.0.0.0:${PORT} (${NODE_ENV})`);
  console.log(`CSP connect-src allows: ${CONNECT_SRC.join(', ')}`);
  if (AUTH_DISABLED) console.log('⚠️  AUTH is DISABLED for this process (dev bypass).');
});

