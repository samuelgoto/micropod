// Baseline headers we always allow. Clients (notably bsky.app) add new custom
// request headers over time (e.g. `x-atproto-session-id`), so on preflight we
// also echo back whatever the browser asks for in Access-Control-Request-Headers.
const DEFAULT_ALLOWED_HEADERS = [
  'Content-Type',
  'Authorization',
  'DPoP',
  'atproto-accept-labelers',
  'atproto-proxy-type',
  'atproto-proxy',
  'atproto-proxy-exp',
  'atproto-content-type',
  'x-atproto-session-id',
  'x-bsky-topics',
  'x-bsky-active-labelers',
].join(', ');

const EXPOSED_HEADERS = [
  'atproto-content-type',
  'atproto-proxy',
  'atproto-proxy-exp',
  'atproto-repo-rev',
  'x-bsky-topics',
  'x-bsky-active-labelers',
  'DPoP-Nonce',
  'WWW-Authenticate',
  'RateLimit-Limit',
  'RateLimit-Remaining',
  'RateLimit-Reset',
  'RateLimit-Policy',
].join(', ');

export default (req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, POST, OPTIONS, PUT, DELETE');
  const requestedHeaders = req.headers['access-control-request-headers'];
  res.setHeader('Access-Control-Allow-Headers', requestedHeaders || DEFAULT_ALLOWED_HEADERS);
  res.setHeader('Access-Control-Expose-Headers', EXPOSED_HEADERS);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Max-Age', '600');
    return res.sendStatus(204);
  }
  next();
};
