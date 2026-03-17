// services/auth/middleware.js
// requireAuth and requireAdmin Express middleware for SSO-gated routes
'use strict';

/**
 * Require an authenticated session before serving the app.
 *
 * SSO is opt-in: if AZURE_CLIENT_ID is not set, authentication is
 * skipped entirely and the dashboard is served without login.
 * In non-production mode, a synthetic dev session is created for
 * convenience (visible in the UI as "Dev User").
 */
function requireAuth(req, res, next) {
  // SSO is opt-in — if Azure is not configured, skip auth entirely
  if (!process.env.AZURE_CLIENT_ID) {
    if (process.env.NODE_ENV !== 'production' && !req.session.user) {
      req.session.user = { name: 'Dev User', email: 'dev@localhost', oid: 'dev' };
    }
    return next();
  }
  if (req.session && req.session.user) return next();
  // API-style requests get a 401 JSON response
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  // Store intended destination so we can redirect back after login
  req.session.returnTo = req.originalUrl;
  res.redirect('/login');
}

/**
 * Require admin privileges. Checks req.session.user.email against
 * the ADMIN_EMAILS env var (comma-separated). If ADMIN_EMAILS is not set,
 * all authenticated users are allowed (no restriction).
 */
function requireAdmin(req, res, next) {
  const adminList = process.env.ADMIN_EMAILS;
  if (!adminList) return next(); // no list configured — allow all authenticated users
  const allowed = adminList.split(',').map(e => e.trim().toLowerCase());
  const userEmail = req.session && req.session.user && req.session.user.email
    ? req.session.user.email.toLowerCase()
    : null;
  if (userEmail && allowed.includes(userEmail)) return next();
  if (req.originalUrl.startsWith('/api/')) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  res.status(403).send('Forbidden');
}

module.exports = { requireAuth, requireAdmin };
