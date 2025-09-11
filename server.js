/* Simple static server for the SERP Matrix dashboard */
const path = require('path');
const express = require('express');
const compression = require('compression');
const helmet = require('helmet');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust Railway/Proxy
app.set('trust proxy', 1);

// Security headers (CSP is OFF by default so inline CSS/JS works)
app.use(helmet());

// Gzip/Brotli (Brotli is handled by platform; gzip here)
app.use(compression());

// Logging
app.use(morgan(process.env.NODE_ENV === 'production' ? 'tiny' : 'dev'));

// Parse JSON just in case you later add small endpoints
app.use(express.json({ limit: '1mb' }));

// Static assets
const publicDir = path.join(__dirname, 'public');
const staticOpts = {
  etag: true,
  lastModified: true,
  maxAge: '1h',
  setHeaders: (res, filePath) => {
    // Always serve index.html fresh to avoid stale embedded JSON
    if (filePath.endsWith('index.html')) {
      res.setHeader('Cache-Control', 'no-store');
    }
  }
};

app.use(express.static(publicDir, staticOpts));

// Health check
app.get(['/health', '/healthz', '/_health'], (_req, res) =>
  res.status(200).json({ ok: true })
);

// Fallback to index (not strictly needed, but handy)
app.get('*', (_req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`SERP Report Viewer running on http://0.0.0.0:${PORT}`);
});
