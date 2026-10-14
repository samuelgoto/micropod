import express from 'express';
import axios from 'axios';
import { createServiceAuthToken, auth, oauth } from './auth.js';
import { isSafeUrl } from './util.js';

const router = express.Router();
const serviceCache = new Map();

const resolveServiceEndpoint = async (didWithFragment) => {
  if (serviceCache.has(didWithFragment)) {
      const cached = serviceCache.get(didWithFragment);
      if (Date.now() - cached.time < 3600000) return cached.url; // Cache for 1 hour
  }

  try {
    const [did, fragment] = didWithFragment.split('#');
    let doc;

    if (did.startsWith('did:web:')) {
      const domain = did.split(':').pop();
      const res = await axios.get(`https://${domain}/.well-known/did.json`, { timeout: 5000 });
      doc = res.data;
    } else if (did.startsWith('did:plc:')) {
      const res = await axios.get(`https://plc.directory/${did}`, { timeout: 5000 });
      doc = res.data;
    } else {
      return null;
    }

    if (!doc || !doc.service) return null;

    let endpoint = null;
    if (fragment) {
      const serviceId = `#${fragment}`;
      const service = doc.service.find(s => s.id === serviceId || s.id === didWithFragment || s.id === `#${didWithFragment}`);
      endpoint = service?.serviceEndpoint || null;
    }

    if (!endpoint) {
      const atprotoService = doc.service.find(s => s.type === 'AtprotoPersonalDataServer' || s.type === 'BskyAppView');
      endpoint = atprotoService?.serviceEndpoint || doc.service[0]?.serviceEndpoint || null;
    }

    if (endpoint) {
        serviceCache.set(didWithFragment, { url: endpoint, time: Date.now() });
    }
    return endpoint;
  } catch (err) {
    console.error(`[RESOLVE_SERVICE] Failed to resolve service for ${didWithFragment}:`, err.message);
    return null;
  }
};

// --- Generic XRPC Proxy Middleware (Fallthrough) ---
// Only requests carrying an atproto-proxy header are proxied. Those requests are
// signed with the account's repo key (service auth), so they MUST be
// authenticated as the account owner first.
const requireProxyHeader = (req, res, next) => (req.headers['atproto-proxy'] ? next() : next('route'));

router.all(/^\/xrpc\/.*/, requireProxyHeader, auth, oauth('atproto'), async (req, res, next) => {
  const proxyTargetDid = req.headers['atproto-proxy'];
  
  const method = req.path.replace('/xrpc/', '');
  const targetUrl = await resolveServiceEndpoint(proxyTargetDid);
  if (!targetUrl || !isSafeUrl(targetUrl)) {
    console.warn(`[PROXY] Invalid or unsafe endpoint for ${proxyTargetDid}: ${targetUrl}`);
    return res.status(502).json({ error: 'ProxyError', message: `Could not resolve safe endpoint for ${proxyTargetDid}` });
  }

  // Identify user for Service Auth 'sub' claim (validated by the auth middleware)
  const userDid = req.user.auth.sub;

  const forwardHeaders = {};
  const whitelist = [
      'accept', 'accept-encoding', 'accept-language', 'user-agent',
      'atproto-accept-labelers', 'atproto-content-type',
      'content-type'
  ];
  
  for (const key of whitelist) {
      if (req.headers[key]) forwardHeaders[key] = req.headers[key];
  }

  // Add Service Authentication
  const serviceToken = await createServiceAuthToken(proxyTargetDid, method, userDid);
  forwardHeaders['authorization'] = `Bearer ${serviceToken}`;

  const response = await axios({
    method: req.method,
    url: `${targetUrl}${req.path}`,
    data: (req.method === 'GET' || req.method === 'HEAD') ? undefined : req.body,
    headers: forwardHeaders,
    params: req.query,
    responseType: 'arraybuffer',
    validateStatus: () => true,
  });

  if (response.status >= 400) {
      console.error(`[PROXY] Target responded with error: ${response.status} for ${req.path}`);
  }

  // Forward response headers, but keep our own CORS headers (set by cors.js)
  // and drop hop-by-hop / encoding headers that no longer match the body.
  const skipHeaders = new Set([
    'connection', 'keep-alive', 'transfer-encoding', 'content-encoding',
    'content-length', 'vary',
  ]);
  Object.entries(response.headers).forEach(([key, value]) => {
    const lower = key.toLowerCase();
    if (skipHeaders.has(lower) || lower.startsWith('access-control-')) return;
    res.setHeader(key, value);
  });

  res.status(response.status).send(response.data);
});

export default router;
