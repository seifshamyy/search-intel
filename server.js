/* server.js — static server with CSP that allows direct fetch to your webhook,
   wired with the security middleware above (IP allow-list + daily password + 9am notifier).
*/
const path = require('path');
const express = require('express');
const compression = require('compression');
const morgan = require('morgan');
const helmet = require('helmet');
const secure = require('./security');

const app = express();
const PORT = process.env.PORT || 3000;

// Allow direct outbound fetch from the browser to your data webhook (for the dashboard button).
// Add more origins by setting CONNECT_SRC env to a comma-separated list.
const CONNECT_SRC = (process.env.CONNECT_SRC || 'https://primary-production-9e01d.up.railway.app')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// Apply security: IP allow-list + Basic Auth + daily notifier (no HTML changes).
secure(app);

// Standard hardening; CSP permits inline script/style in your current HTML.
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'", "https:"],
        "style-src": ["'self'", "'unsafe-inline'", "https:"],
        "img-src": ["'self'", "data:", "https:"],
        "connect-src": ["'self'", ...CONNECT_SRC], // allow direct fetch to webhook
        "frame-ancestors": ["'none'"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"]
      }
    },
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginEmbedderPolicy: false
  })
);

app.use(compression());
app.use(morgan(process.env.NODE_ENV === 'production' ? 'tiny' : 'dev'));
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
        res.setHeader('Cache-Control', 'no-store'); // serve fresh dashboard HTML
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
  console.log(`Static app running on http://0.0.0.0:${PORT}`);
  console.log(`CSP connect-src allows: ${CONNECT_SRC.join(', ')}`);
});
