import express from 'express';
import { db } from './db.js';
import { createToken, validateDpop, verifyToken } from './auth.js';
import { createHash, createHmac, randomBytes, createECDH, createPublicKey, timingSafeEqual } from 'crypto';
import axios from 'axios';
import { getDidDoc, verifyPassword, isSafeUrl, escapeHtml } from './util.js';
import { rateLimit } from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { createSession, getLoginUrl, setSessionCookie } from './session.js';
import {
  getOauthEs256kKeypair,
  getOauthEs256kPrivateKeyHex,
  getOauthEs256kPublicJwk,
  getOptionalRs256PrivateKey,
  getOptionalRs256PublicJwk,
  getSupportedAuthorizationSigningAlgs,
} from './oauth-keys.js';

const router = express.Router();

const oauthLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	limit: 1000, // Increased to 1000 for convenience
	standardHeaders: true,
	legacyHeaders: false,
  validate: { trustProxy: false },
  message: { error: 'RateLimitExceeded', message: 'Too many attempts. Please try again later.' }
});

const clientKeyCache = new Map();

async function signAuthorizationResponseJwt(payload, alg, user) {
  if (alg === 'ES256K') {
    const header = { typ: 'oauth-authz-resp+jwt', alg: 'ES256K' };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const data = Buffer.from(`${headerB64}.${payloadB64}`);

    const keypair = await getOauthEs256kKeypair();
    const sig = await keypair.sign(data);
    const sigB64 = Buffer.from(sig).toString('base64url');
    return `${headerB64}.${payloadB64}.${sigB64}`;
  }

  if (alg === 'RS256') {
    const privateKey = getOptionalRs256PrivateKey();
    const jwk = getOptionalRs256PublicJwk();
    if (!privateKey || !jwk) {
      throw new Error('RS256 authorization signing requested but OAUTH_RS256_PRIVATE_KEY is not configured');
    }

    return jwt.sign(payload, privateKey, {
      algorithm: 'RS256',
      header: {
        typ: 'oauth-authz-resp+jwt',
        alg: 'RS256',
        kid: jwk.kid,
      },
    });
  }

  throw new Error(`Unsupported authorization response signing algorithm: ${alg}`);
}

export async function createAccessToken(did, handle, jkt, issuer, client_id, scope) {
  // ATProto OAuth nuance: The resource server identifier is its did:web
  const pdsHost = issuer.replace(/^https?:\/\//, '');
  const pdsDidWeb = `did:web:${pdsHost}`;
  const privKeyHex = getOauthEs256kPrivateKeyHex();
  
  const payload = {
    iss: issuer,
    sub: did,
    aud: [pdsDidWeb, client_id], // Identifying the PDS by its did:web
    handle,
    cnf: { jkt },
    scope: scope || 'atproto',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };

  const header = { typ: 'JWT', alg: 'ES256K' };
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const data = Buffer.from(`${headerB64}.${payloadB64}`);

  const keypair = await getOauthEs256kKeypair();
  const sig = await keypair.sign(data);
  const sigB64 = Buffer.from(sig).toString('base64url');

  return `${headerB64}.${payloadB64}.${sigB64}`;
}

export async function createIdToken(did, handle, client_id, issuer) {
  const privKeyHex = getOauthEs256kPrivateKeyHex();
  if (!privKeyHex) throw new Error('No OAuth ES256K private key');
  if (!client_id) throw new Error('client_id is required for id_token');

  const payload = {
    iss: issuer,
    sub: did,
    aud: client_id,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    name: handle,
    preferred_username: handle
  };

  const header = { typ: 'JWT', alg: 'ES256K' };
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const data = Buffer.from(`${headerB64}.${payloadB64}`);

  const keypair = await getOauthEs256kKeypair();
  const sig = await keypair.sign(data);
  const sigB64 = Buffer.from(sig).toString('base64url');

  return `${headerB64}.${payloadB64}.${sigB64}`;
}

// Schemes that must never be accepted as an OAuth redirect target (they would
// execute script in our origin when used in links / redirects).
const FORBIDDEN_REDIRECT_SCHEMES = new Set(['javascript:', 'data:', 'vbscript:', 'file:', 'blob:']);

export const isAllowedRedirectUri = (value) => {
  if (typeof value !== 'string' || value.length === 0) return false;
  try {
    const url = new URL(value);
    return !FORBIDDEN_REDIRECT_SCHEMES.has(url.protocol);
  } catch {
    return false;
  }
};

// Only allow http(s) URLs to be rendered as links/images on the consent page.
const safeHttpUrl = (value) => {
  if (typeof value !== 'string') return '';
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.toString() : '';
  } catch {
    return '';
  }
};

/**
 * Fetches and validates OAuth client metadata. Returns null on ANY failure;
 * callers MUST treat null as "reject the request" (fail closed).
 */
const validateClient = async (client_id, redirect_uri) => {
  try {
    if (typeof client_id !== 'string' || !isSafeUrl(client_id)) {
      throw new Error('SSRF Blocked: Invalid or unsafe client_id URL.');
    }

    console.log(`[OAUTH] Validating client: ${client_id} with redirect: ${redirect_uri}`);
    const res = await axios.get(client_id, { 
      timeout: 5000,
      maxRedirects: 3 // Limit redirects to prevent deep chain SSRF
    });
    
    const metadata = res.data;
    if (!metadata || typeof metadata !== 'object') {
      throw new Error('Client metadata is not a JSON object');
    }
    if (metadata.client_id && metadata.client_id !== client_id) {
      throw new Error(`client_id mismatch in metadata: ${metadata.client_id}`);
    }
    if (redirect_uri !== undefined) {
      if (!isAllowedRedirectUri(redirect_uri)) {
        throw new Error('Forbidden redirect_uri scheme');
      }
      if (!Array.isArray(metadata.redirect_uris) || !metadata.redirect_uris.includes(redirect_uri)) {
        console.warn(`[OAUTH] Redirect URI mismatch for ${client_id}. Expected one of: ${metadata.redirect_uris}`);
        throw new Error('Invalid redirect_uri');
      }
    }
    return metadata;
  } catch (err) {
    console.error(`[OAUTH] Client validation failed for ${client_id}:`, err.response?.data || err.message);
    return null;
  }
};

// --- CSRF protection for browser-session approvals ---
// The pds_session cookie is SameSite=None (needed for FedCM), so a browser
// session alone must never be enough to approve a grant. Approvals that rely
// on the session must come from our own origin and carry a token bound to it.
const csrfTokenForSession = (sessionId) => createHmac('sha256', getOauthEs256kPrivateKeyHex() || 'csrf')
  .update(`oauth-authorize-csrf:${sessionId}`)
  .digest('base64url');

const isValidCsrfToken = (sessionId, token) => {
  if (!sessionId || typeof token !== 'string') return false;
  const expected = Buffer.from(csrfTokenForSession(sessionId));
  const actual = Buffer.from(token);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
};

const isSameOriginRequest = (req) => {
  const expectedOrigin = new URL(req.user.issuer).origin;
  const origin = req.get('origin');
  if (origin) return origin === expectedOrigin;
  const referer = req.get('referer');
  if (referer) {
    try { return new URL(referer).origin === expectedOrigin; } catch { return false; }
  }
  return false;
};

const sendAuthorizeError = (res, status, message) => {
  res.status(status).type('text/plain').send(message);
};

router.post('/oauth/par', async (req, res) => {
  const { client_id, redirect_uri } = req.body;
  const metadata = await validateClient(client_id, redirect_uri ?? '');
  if (!metadata) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid client_id or redirect_uri' });
  }
  const request_uri = `urn:ietf:params:oauth:request_uri:${randomBytes(16).toString('hex')}`;
  const expires_at = Math.floor(Date.now() / 1000) + 600; // 10 mins

  await db.execute({
    sql: 'INSERT INTO oauth_par_requests (request_uri, client_id, request_data, expires_at) VALUES (?, ?, ?, ?)',
    args: [request_uri, client_id, JSON.stringify(req.body), expires_at]
  });

  res.status(201).json({ request_uri, expires_in: 600 });
});

router.get('/oauth/authorize', async (req, res) => {
  let query = req.query;
  if (query.request_uri) {
    const par = await db.execute({
      sql: 'SELECT request_data FROM oauth_par_requests WHERE request_uri = ? AND expires_at > ?',
      args: [query.request_uri, Math.floor(Date.now() / 1000)]
    });
    if (par.rows.length === 0) {
      return sendAuthorizeError(res, 400, 'Unknown or expired request_uri');
    }
    query = JSON.parse(par.rows[0].request_data);
  }

  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, response_mode } = query;
  if (typeof client_id !== 'string' || typeof redirect_uri !== 'string') {
    return sendAuthorizeError(res, 400, 'Missing client_id or redirect_uri');
  }

  // Fail closed: never render a consent screen (or redirect anywhere) for a
  // client whose metadata / redirect_uri could not be validated.
  const metadata = await validateClient(client_id, redirect_uri);
  if (!metadata) {
    return sendAuthorizeError(res, 400, 'Invalid client_id or redirect_uri');
  }

  const clientName = (typeof metadata.client_name === 'string' && metadata.client_name) || client_id;
  const logoUri = safeHttpUrl(metadata.logo_uri);
  const isBrowserLoggedIn = Boolean(req.session);

  if (metadata.authorization_signed_response_alg && !getSupportedAuthorizationSigningAlgs().includes(metadata.authorization_signed_response_alg)) {
    return sendAuthorizeError(res, 400, `Unsupported authorization_signed_response_alg: ${metadata.authorization_signed_response_alg}`);
  }

  if (!isBrowserLoggedIn) {
    const returnTo = `${req.path}${req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : ''}`;
    return res.redirect(getLoginUrl(returnTo, { autoReturn: true }));
  }

  const cancelUrl = new URL(redirect_uri);
  cancelUrl.searchParams.set('error', 'access_denied');
  if (state) cancelUrl.searchParams.set('state', state);
  cancelUrl.searchParams.set('iss', req.user.issuer);

  const csrfToken = csrfTokenForSession(req.session.id);
  const h = escapeHtml;

  const getScopeDescription = (s) => {
    const scopes = String(s).split(' ');
    return scopes.map(scopeStr => {
      // Handle Resource Indicators (e.g. scope?aud=...)
      const [scope] = scopeStr.split('?');

      if (scope === 'atproto') return '<li><strong>Full Access</strong>: Read and write everything in your repository.</li>';
      if (scope === 'openid') return '<li><strong>Identity</strong>: Verify your DID and handle.</li>';
      if (scope === 'transition:generic') return '<li><strong>Migration</strong>: Basic access for transitioning from legacy sessions.</li>';
      if (scope === 'transition:email') return '<li><strong>Email</strong>: View and manage your associated email address.</li>';
      if (scope === 'transition:chat.bsky') return '<li><strong>Chat</strong>: Send and receive messages on the Bluesky network.</li>';
      
      // Handle include: scopes (macros) from client metadata
      if (scope.startsWith('include:')) {
        const macroName = scope.replace('include:', '');
        // ATProto nuance: Clients can provide descriptions for these in their metadata
        const desc = metadata?.scope_descriptions?.[macroName] || metadata?.atproto_scope_descriptions?.[macroName];
        if (desc) {
          return `<li><strong>${h(macroName)}</strong>: ${h(desc)}</li>`;
        }
        return `<li><strong>${h(macroName)}</strong>: Additional application-specific permission.</li>`;
      }

      // Handle repo: parameterized scopes
      if (scope.startsWith('repo')) {
        const params = new URLSearchParams(scopeStr.split('?')[1] || '');
        const collection = params.get('collection');
        const action = params.get('action') || 'all';
        return `<li><strong>Repository</strong>: ${h(action)} records in <code>${h(collection || 'all collections')}</code>.</li>`;
      }

      return `<li><strong>${h(scope)}</strong>: Additional permission.</li>`;
    }).join('');
  };

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Authorize Application</title>
      <link rel="icon" href="/favicon.ico" sizes="any">
      <style>
        :root {
          color-scheme: light;
          --bg: #f3f5f7;
          --card: #ffffff;
          --ink: #111827;
          --muted: #4b5563;
          --line: #d1d5db;
          --accent: #0f172a;
          --accent-soft: #e5e7eb;
        }
        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: radial-gradient(circle at top, #dbeafe, #f8fafc 45%);
          color: var(--ink);
          min-height: 100vh;
          margin: 0;
          display: grid;
          place-items: center;
          padding: 24px;
        }
        .card {
          width: min(520px, 100%);
          background: var(--card);
          border: 1px solid var(--line);
          border-radius: 18px;
          padding: 28px;
          box-shadow: 0 20px 60px rgba(15, 23, 42, 0.08);
        }
        .eyebrow {
          margin: 0 0 6px;
          color: var(--muted);
          font-size: 0.95rem;
        }
        .header {
          display: flex;
          align-items: center;
          gap: 1rem;
          margin-bottom: 1rem;
        }
        .logo {
          width: 56px;
          height: 56px;
          border-radius: 14px;
          background: linear-gradient(135deg, #0f172a, #2563eb);
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: 700;
          color: #fff;
          flex-shrink: 0;
          overflow: hidden;
          border: 1px solid var(--line);
        }
        .logo img {
          width: 100%;
          height: 100%;
          object-fit: cover;
        }
        h1 {
          font-size: 1.4rem;
          margin: 0;
          color: var(--ink);
          line-height: 1.2;
        }
        p {
          color: var(--muted);
          line-height: 1.5;
          font-size: 0.95rem;
          margin: 0 0 16px;
        }
        .client-id {
          font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
          color: var(--muted);
          font-size: 0.8rem;
          word-break: break-all;
          margin-top: 6px;
        }
        .scope-list {
          background: #f8fafc;
          padding: 1rem 1.1rem;
          border-radius: 12px;
          border: 1px solid var(--line);
          margin: 1.25rem 0 1.5rem;
        }
        .scope-list ul {
          margin: 0;
          padding-left: 1.2rem;
        }
        .scope-list li {
          margin-bottom: 0.6rem;
          font-size: 0.9rem;
          color: var(--ink);
        }
        .scope-list li:last-child {
          margin-bottom: 0;
        }
        .actions {
          display: flex;
          gap: 12px;
          flex-wrap: wrap;
        }
        button, .link-button {
          appearance: none;
          border: 0;
          border-radius: 999px;
          padding: 10px 16px;
          font: inherit;
          text-decoration: none;
          cursor: pointer;
        }
        button {
          background: var(--accent);
          color: #fff;
        }
        .link-button {
          background: var(--accent-soft);
          color: var(--ink);
        }
        .meta-links {
          margin-top: 18px;
          display: flex;
          flex-direction: column;
          gap: 8px;
        }
        .meta-links a {
          color: var(--muted);
          text-decoration: none;
          font-size: 0.9rem;
        }
        .meta-links a:hover {
          text-decoration: underline;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <p class="eyebrow">Authorize application access</p>
        <div class="header">
          <div class="logo">
            ${logoUri ? `<img src="${h(logoUri)}" alt="">` : h(clientName[0].toUpperCase())}
          </div>
          <div>
            <h1>${h(clientName)}</h1>
            <div class="client-id">${h(client_id)}</div>
          </div>
        </div>
        
        <p>${h(clientName)} wants to access your <strong>${h(req.user.handle)}</strong> account.</p>
        
        <div class="scope-list">
          <ul>${getScopeDescription(scope || 'atproto')}</ul>
        </div>

        <form method="POST" action="/oauth/authorize">
          <input type="hidden" name="csrf_token" value="${h(csrfToken)}">
          <input type="hidden" name="client_id" value="${h(client_id)}">
          <input type="hidden" name="redirect_uri" value="${h(redirect_uri)}">
          <input type="hidden" name="scope" value="${h(scope ?? '')}">
          <input type="hidden" name="state" value="${h(state ?? '')}">
          <input type="hidden" name="code_challenge" value="${h(code_challenge ?? '')}">
          <input type="hidden" name="code_challenge_method" value="${h(code_challenge_method || '')}">
          <input type="hidden" name="response_mode" value="${h(response_mode || '')}">
          <div class="actions">
            <button type="submit">Authorize</button>
            <a class="link-button" href="${h(cancelUrl.toString())}">Cancel</a>
          </div>
        </form>
        
        <div class="meta-links">
          ${safeHttpUrl(metadata.client_uri) ? `<a href="${h(safeHttpUrl(metadata.client_uri))}" target="_blank" rel="noopener noreferrer">About the Application</a>` : ''}
          ${safeHttpUrl(metadata.policy_uri) ? `<a href="${h(safeHttpUrl(metadata.policy_uri))}" target="_blank" rel="noopener noreferrer">Privacy Policy</a>` : ''}
          ${safeHttpUrl(metadata.tos_uri) ? `<a href="${h(safeHttpUrl(metadata.tos_uri))}" target="_blank" rel="noopener noreferrer">Terms of Service</a>` : ''}
        </div>
      </div>
    </body>
    </html>
  `);
});

router.post('/oauth/authorize', oauthLimiter, async (req, res) => {
  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, response_mode, password, csrf_token } = req.body;
  const user = req.user;
  if (!user) {
    return res.status(401).send('Invalid password');
  }

  // Two ways to approve a grant:
  //  1. The account password is supplied with the request (cannot be forged cross-site).
  //  2. An existing browser session, BUT only from our own consent page: the
  //     request must be same-origin and carry the CSRF token bound to the session.
  //     (The session cookie is SameSite=None, so it is sent on cross-site POSTs.)
  const passwordOk = typeof password === 'string' && password.length > 0 && verifyPassword(password, user.password);
  const hasBrowserSession = Boolean(req.session);
  if (!passwordOk) {
    if (!hasBrowserSession) {
      return res.status(401).send('Invalid password');
    }
    if (!isSameOriginRequest(req) || !isValidCsrfToken(req.session.id, csrf_token)) {
      console.warn('[OAUTH] Rejected cross-site or tokenless authorization approval', {
        origin: req.get('origin') || null,
        referer: req.get('referer') || null,
        client_id,
      });
      return sendAuthorizeError(res, 403, 'Authorization must be approved from the consent screen');
    }
  }

  // ATProto OAuth requires PKCE with S256.
  if (typeof code_challenge !== 'string' || code_challenge.length < 43 || code_challenge_method !== 'S256') {
    return sendAuthorizeError(res, 400, 'PKCE (S256 code_challenge) is required');
  }

  // 1. Validate client and get metadata for JARM check. Fail closed: never
  //    issue a code or redirect to an unvalidated redirect_uri.
  const metadata = await validateClient(client_id, redirect_uri ?? '');
  console.log(`[OAUTH] Metadata for ${client_id}:`, metadata);
  if (!metadata) {
    return sendAuthorizeError(res, 400, 'Invalid client_id or redirect_uri');
  }

  if (!hasBrowserSession) {
    const { sessionId } = await createSession(user);
    setSessionCookie(res, sessionId);
  }

  if (metadata.authorization_signed_response_alg && !getSupportedAuthorizationSigningAlgs().includes(metadata.authorization_signed_response_alg)) {
    return res.status(400).json({
      error: 'invalid_request',
      message: `Unsupported authorization_signed_response_alg: ${metadata.authorization_signed_response_alg}`
    });
  }

  const code = randomBytes(16).toString('hex');
  const expires_at = Math.floor(Date.now() / 1000) + 600;

  await db.execute({
    sql: 'INSERT INTO oauth_codes (code, client_id, redirect_uri, scope, did, dpop_jwk, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    args: [code, client_id, redirect_uri, scope || 'atproto', user.did, code_challenge || '', expires_at]
  });

  const url = new URL(redirect_uri);
  
  // 2. Handle Signed Authorization Response (JARM)
  if (metadata?.authorization_signed_response_alg) {
    const payload = {
      iss: req.user.issuer,
      aud: client_id,
      code,
      state,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 600,
    };
    const responseJwt = await signAuthorizationResponseJwt(payload, metadata.authorization_signed_response_alg, user);

    url.searchParams.set('response', responseJwt);
  } else {
    // Standard response
    url.searchParams.set('code', code);
    if (state) url.searchParams.set('state', state);
    url.searchParams.set('iss', req.user.issuer);
  }

  if (response_mode === 'fragment') {
    const params = new URLSearchParams(url.search);
    url.search = '';
    url.hash = params.toString();
  }
  
  console.log(`[OAUTH] Redirecting to ${url.toString()}`);
  res.redirect(url.toString());
});

router.post('/oauth/token', oauthLimiter, async (req, res) => {
    let { grant_type, code, client_id, redirect_uri, refresh_token, code_verifier, client_assertion, client_assertion_type } = req.body;
    const user = req.user;
    const issuer = user.issuer;
    const requestId = req.get('x-request-id') || 'no-request-id';

    console.log('[OAUTH_TOKEN] Request received', {
      requestId,
      grant_type,
      client_id: client_id || null,
      redirect_uri: redirect_uri || null,
      has_code: Boolean(code),
      has_refresh_token: Boolean(refresh_token),
      has_code_verifier: Boolean(code_verifier),
      has_dpop: Boolean(req.headers.dpop),
      has_client_assertion: Boolean(client_assertion),
      client_assertion_type: client_assertion_type || null,
    });

    // 1. Support private_key_jwt authentication
    if (client_assertion_type === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' && client_assertion) {
      try {
        const decoded = jwt.decode(client_assertion, { complete: true });
        if (!decoded) throw new Error('Invalid client_assertion');
        
        client_id = decoded.payload.iss; // client_id MUST be the issuer
        console.log('[OAUTH_TOKEN] Client assertion decoded', {
          requestId,
          client_id,
          alg: decoded.header?.alg || null,
          kid: decoded.header?.kid || null,
          aud: decoded.payload?.aud || null,
          sub: decoded.payload?.sub || null,
        });
        
        // ATProto nuance: aud must be the issuer or the token endpoint
        const expectedAud = [issuer, `${issuer}/oauth/token` ];
        const actualAud = Array.isArray(decoded.payload.aud) ? decoded.payload.aud : [decoded.payload.aud];
        if (!actualAud.some((aud) => expectedAud.includes(aud))) {
            throw new Error(`Invalid audience in client_assertion: expected one of ${expectedAud}, got ${actualAud}`);
        }

        const metadata = await validateClient(client_id, undefined); // No redirect_uri check yet
        
        if (!metadata || metadata.token_endpoint_auth_method !== 'private_key_jwt') {
            throw new Error('Client does not support private_key_jwt');
        }

        // Fetch JWKS and verify
        let jwks = metadata.jwks;
        if (!jwks && clientKeyCache.has(metadata.jwks_uri)) {
            jwks = clientKeyCache.get(metadata.jwks_uri);
        } else if (!jwks && metadata.jwks_uri) {
            const jwksRes = await axios.get(metadata.jwks_uri);
            jwks = jwksRes.data;
            clientKeyCache.set(metadata.jwks_uri, jwks);
        }

        if (!jwks || !Array.isArray(jwks.keys)) {
            throw new Error('Client JWKS not available');
        }

        console.log('[OAUTH_TOKEN] Client assertion JWKS loaded', {
          requestId,
          client_id,
          jwks_uri: metadata.jwks_uri || null,
          jwk_count: jwks.keys.length,
        });

        const key = jwks.keys.find(k => k.kid === decoded.header.kid);
        if (!key) throw new Error('Matching key not found in JWKS');

        console.log('[OAUTH_TOKEN] Client assertion key selected', {
          requestId,
          client_id,
          kid: key.kid || null,
          kty: key.kty,
          crv: key.crv || null,
          alg: key.alg || null,
        });

        // Note: Minimal implementation. In production, use jwks-rsa or similar.
        // For ES256, we can use the multikey format if it's already there
        if (key.kty === 'EC' && key.crv === 'P-256') {
             // Basic validation that it's signed correctly
             jwt.verify(client_assertion, createPublicKey({ key, format: 'jwk' }), { algorithms: ['ES256'] });
             console.log('[OAUTH_TOKEN] Client assertion verified', { requestId, client_id, alg: 'ES256' });
        } else {
             throw new Error('Unsupported key type in JWKS');
        }
      } catch (err) {
        console.error('[OAUTH_TOKEN] Client assertion failed:', err.message);
        return res.status(401).json({ error: 'invalid_client', message: err.message });
      }
    }

    let jkt;
    try {
      ({ jkt } = await validateDpop(req));
    } catch (err) {
      console.error('[OAUTH_TOKEN] DPoP validation failed:', err.message);
      return res.status(400).json({ error: 'invalid_dpop_proof', message: err.message });
    }

    if (grant_type === 'authorization_code') {
      const result = await db.execute({
        sql: 'SELECT * FROM oauth_codes WHERE code = ? AND client_id = ? AND expires_at > ?',
        args: [code, client_id, Math.floor(Date.now() / 1000)]
      });

      if (result.rows.length === 0) {
        return res.status(400).json({ error: 'invalid_grant' });
      }

      const row = result.rows[0];
      console.log('[OAUTH_TOKEN] Authorization code loaded', {
        requestId,
        client_id,
        did: row.did,
        scope: row.scope,
        format: row.format || 'atproto',
        pkce_bound: Boolean(row.dpop_jwk),
      });

      if (row.dpop_jwk) {
        if (!code_verifier) return res.status(400).json({ error: 'invalid_request', message: 'Missing code_verifier' });
        const hash = createHash('sha256').update(code_verifier).digest('base64url');
        if (hash !== row.dpop_jwk) {
            return res.status(400).json({ error: 'invalid_grant', message: 'PKCE verification failed' });
        }
        console.log('[OAUTH_TOKEN] PKCE verification passed', { requestId, client_id });
      }

      if (row.format !== 'indieauth') {
        // ATProto OAuth: PKCE and DPoP are mandatory, and redirect_uri must match.
        if (!row.dpop_jwk) {
          return res.status(400).json({ error: 'invalid_grant', message: 'Authorization code was not PKCE-bound' });
        }
        if (!jkt) {
          return res.status(400).json({ error: 'invalid_dpop_proof', message: 'DPoP proof is required' });
        }
        if (redirect_uri && row.redirect_uri && redirect_uri !== row.redirect_uri) {
          return res.status(400).json({ error: 'invalid_grant', message: 'redirect_uri mismatch' });
        }
      }

      if (row.format === 'indieauth') {
        const accessToken = await createToken(row.did, user.handle);
        let profile = {};
        try {
          profile = JSON.parse(row.profile || '{}');
        } catch {
          profile = {};
        }

        await db.execute({ sql: 'DELETE FROM oauth_codes WHERE code = ?', args: [code] });

        return res.json({
          me: row.me,
          profile,
          access_token: accessToken,
          token_type: 'Bearer',
          scope: row.scope,
        });
      }

      const access_token = await createAccessToken(row.did, user.handle, jkt, issuer, client_id, row.scope);
      const new_refresh_token = randomBytes(32).toString('hex');

      await db.execute({
        sql: 'INSERT INTO oauth_refresh_tokens (token, client_id, did, scope, dpop_jwk, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
        args: [new_refresh_token, client_id, row.did, row.scope, jkt || '', Math.floor(Date.now() / 1000) + 30 * 24 * 3600]
      });

      await db.execute({ sql: 'DELETE FROM oauth_codes WHERE code = ?', args: [code] });

      const response = {
        access_token,
        token_type: 'DPoP',
        expires_in: 3600,
        refresh_token: new_refresh_token,
        scope: row.scope,
        sub: row.did,
        did: row.did
      };

      if (row.scope.includes('openid')) {
        response.id_token = await createIdToken(row.did, user.handle, client_id, issuer);
      }

      console.log('[OAUTH_TOKEN] Authorization code exchanged', {
        requestId,
        client_id,
        did: row.did,
        token_type: response.token_type,
        scope: response.scope,
        has_id_token: Boolean(response.id_token),
      });
      res.json(response);
    } else if (grant_type === 'refresh_token') {
       const result = await db.execute({
        sql: 'SELECT * FROM oauth_refresh_tokens WHERE token = ? AND client_id = ? AND expires_at > ?',
        args: [refresh_token, client_id, Math.floor(Date.now() / 1000)]
      });

      if (result.rows.length === 0) {
        return res.status(400).json({ error: 'invalid_grant' });
      }

      const row = result.rows[0];
      if (!jkt || (row.dpop_jwk || '') !== jkt) {
        return res.status(400).json({ error: 'invalid_dpop_key' });
      }

      const access_token = await createAccessToken(row.did, user.handle, jkt, issuer, client_id, row.scope);
      const new_refresh_token = randomBytes(32).toString('hex');

      await db.execute({
        sql: 'UPDATE oauth_refresh_tokens SET token = ?, expires_at = ? WHERE token = ?',
        args: [new_refresh_token, Math.floor(Date.now() / 1000) + 30 * 24 * 3600, refresh_token]
      });

      const response = {
        access_token,
        token_type: 'DPoP',
        expires_in: 3600,
        refresh_token: new_refresh_token,
        scope: row.scope,
        sub: row.did,
        did: row.did
      };

      if (row.scope.includes('openid')) {
        response.id_token = await createIdToken(row.did, user.handle, client_id, issuer);
      }

      console.log('[OAUTH_TOKEN] Refresh token exchanged', {
        requestId,
        client_id,
        did: row.did,
        token_type: response.token_type,
        scope: response.scope,
        has_id_token: Boolean(response.id_token),
      });
      res.json(response);
    } else {
      res.status(400).json({ error: 'unsupported_grant_type' });
    }
});

router.get('/.well-known/oauth-authorization-server', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  const issuer = req.user.issuer;
  const authorizationSigningAlgs = getSupportedAuthorizationSigningAlgs();
  
  res.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    pushed_authorization_request_endpoint: `${issuer}/oauth/par`,
    require_pushed_authorization_requests: true,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    scopes_supported: ['atproto', 'openid'],
    response_types_supported: ['code'],
    response_modes_supported: ['query', 'fragment', 'jwt'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none', 'client_id_metadata_document', 'private_key_jwt'],
    token_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256', 'ES256K'],
    dpop_signing_alg_values_supported: ['RS256', 'ES256', 'ES256K'],
    authorization_signing_alg_values_supported: authorizationSigningAlgs,
    code_challenge_methods_supported: ['S256'],
    authorization_response_iss_parameter_supported: true,
    client_id_metadata_document_supported: true,
    protected_resources: [issuer]
  });
});

router.get('/.well-known/oauth-protected-resource', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  const issuer = req.user.issuer;

  res.json({
    resource: issuer,
    authorization_servers: [issuer],
    scopes_supported: ['atproto'],
    bearer_methods_supported: ['header'],
    resource_documentation: 'https://atproto.com/specs/oauth'
  });
});

router.get('/.well-known/openid-configuration', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  const issuer = req.user.issuer;

  res.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    scopes_supported: ['openid', 'atproto'],
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256']
  });
});

router.get('/.well-known/jwks.json', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  
  const keys = [await getOauthEs256kPublicJwk()];

  const rs256Jwk = getOptionalRs256PublicJwk();
  if (rs256Jwk) {
    keys.push(rs256Jwk);
  }

  res.json({
    keys
  });
});

export default router;
