// services/auth/routes.js
// Azure Entra ID (MSAL) OAuth2 routes: /auth/login, /auth/callback, /auth/logout
'use strict';

const { Router } = require('express');
const { ConfidentialClientApplication } = require('@azure/msal-node');
const { randomUUID } = require('node:crypto');

const router = Router();
const BASE_SCOPES = ['openid', 'profile', 'email'];

let _msalClient;
function getMsalClient() {
  if (!_msalClient) {
    _msalClient = new ConfidentialClientApplication({
      auth: {
        clientId: process.env.AZURE_CLIENT_ID,
        authority: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}`,
        clientSecret: process.env.AZURE_CLIENT_SECRET,
      },
    });
  }
  return _msalClient;
}

/**
 * Parse ALLOWED_GROUPS env var (comma-separated Azure group OIDs).
 * Returns a Set of IDs, or null if not configured (= no group restriction).
 */
function parseAllowedGroups() {
  const raw = process.env.ALLOWED_GROUPS;
  if (!raw) return null;
  const ids = raw.split(',').map(s => s.trim()).filter(Boolean);
  return ids.length ? new Set(ids) : null;
}

async function checkGroupMembership(accessToken, allowedGroups) {
  const res = await fetch('https://graph.microsoft.com/v1.0/me/memberOf?$select=id', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const data = await res.json();
  const userGroups = (data.value || []).map(g => g.id);
  return userGroups.some(id => allowedGroups.has(id));
}

// Step 1: Redirect to Azure AD
router.get('/login', async (req, res) => {
  const state = randomUUID();
  req.session.oauthState = state;
  const scopes = [...BASE_SCOPES];
  if (parseAllowedGroups()) scopes.push('GroupMember.Read.All');
  try {
    const authUrl = await getMsalClient().getAuthCodeUrl({
      scopes,
      redirectUri: process.env.REDIRECT_URI,
      state,
      prompt: 'select_account',
    });
    res.redirect(authUrl);
  } catch (err) {
    console.error('Failed to build Azure auth URL:', err.message);
    res.redirect('/login?error=1');
  }
});

// Step 2: Azure AD redirects back here with auth code
router.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!state || state !== req.session.oauthState) {
    return res.status(403).send('Invalid OAuth state — possible CSRF attempt');
  }
  delete req.session.oauthState;

  try {
    const scopes = [...BASE_SCOPES];
    if (parseAllowedGroups()) scopes.push('GroupMember.Read.All');
    const result = await getMsalClient().acquireTokenByCode({
      code,
      scopes,
      redirectUri: process.env.REDIRECT_URI,
    });

    // Optional: enforce Azure AD group membership
    const allowedGroups = parseAllowedGroups();
    if (allowedGroups) {
      const isMember = await checkGroupMembership(result.accessToken, allowedGroups);
      if (!isMember) {
        req.session.destroy(() => {});
        return res.redirect('/login?denied=1');
      }
    }

    req.session.user = {
      name: result.account.name,
      email: result.account.username,
      oid: result.account.homeAccountId,
    };

    // Redirect to the original destination (safe path only)
    const raw = req.session.returnTo || '/';
    const safe = (raw.startsWith('/') && !raw.startsWith('//')) ? raw : '/';
    delete req.session.returnTo;
    res.redirect(safe);
  } catch (err) {
    console.error('Auth callback error:', err.message);
    res.redirect('/login?error=1');
  }
});

// Logout: destroy session and return to login page
router.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login?logout=1');
  });
});

module.exports = router;
