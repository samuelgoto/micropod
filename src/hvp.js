import express from 'express';
import { createHash, createPublicKey, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from 'crypto';
import { resolveTxt } from 'dns/promises';
import axios from 'axios';

const router = express.Router();
const PLC_DIRECTORY = 'https://plc.directory';
const REQUIRED_COMPONENTS = ['@method', '@authority', '@path', 'content-digest', 'signature-key'];
const HANDLE_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;

// This signing key intentionally exists only for this Node process. A restart
// rotates the issuer key and invalidates HVTs issued before the restart.
const { privateKey: hvpPrivateKey } = generateKeyPairSync('ed25519');
const hvpPublicJwkRaw = createPublicKey(hvpPrivateKey).export({ format: 'jwk' });
const hvpKeyThumbprint = JSON.stringify({ crv: hvpPublicJwkRaw.crv, kty: hvpPublicJwkRaw.kty, x: hvpPublicJwkRaw.x });
const hvpPublicJwk = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: hvpPublicJwkRaw.x,
  use: 'sig',
  alg: 'Ed25519',
  kid: createHash('sha256').update(hvpKeyThumbprint).digest('base64url'),
};

function getHvpPublicJwk() {
  return hvpPublicJwk;
}

function getHvpPrivateKey() {
  return hvpPrivateKey;
}

function issuerOrigin(req) {
  const configured = (process.env.DOMAIN || '').trim();
  if (configured) {
    const url = new URL(configured.includes('://') ? configured : `https://${configured}`);
    if (url.protocol !== 'https:' || url.username || url.password || url.port || url.pathname !== '/' || url.search || url.hash) {
      throw new Error('DOMAIN must be a hostname or HTTPS origin without a port, path, query, or fragment.');
    }
    return `https://${url.host}`;
  }
  if (process.env.NODE_ENV === 'production') throw new Error('DOMAIN must be configured to publish the HVP issuer.');
  return new URL(req.user.issuer).origin;
}

function errorResponse(res, status, error, message) {
  return res.status(status).type('application/json').json({ error, ...(message ? { error_description: message } : {}) });
}

function parseSignatureInput(value) {
  const match = /^sig=\(([^)]*)\);((?:[a-z][a-z0-9_-]*=(?:\d+|"[^"\\]*"))(?:;[a-z][a-z0-9_-]*=(?:\d+|"[^"\\]*"))*)$/.exec(value || '');
  if (!match) throw new Error('invalid_signature');
  const components = [...match[1].matchAll(/"([^\"]+)"/g)].map((item) => item[1]);
  if (!REQUIRED_COMPONENTS.every((name) => components.includes(name)) || components.some((name) => ![...REQUIRED_COMPONENTS, 'cookie'].includes(name))) {
    throw new Error('invalid_signature');
  }
  if (new Set(components).size !== components.length) throw new Error('invalid_signature');
  const createdValues = [...match[2].matchAll(/(?:^|;)created=(\d+)(?=;|$)/g)];
  if (createdValues.length !== 1) throw new Error('invalid_signature');
  return { components, created: Number(createdValues[0][1]), signatureParams: match[0].slice(4) };
}

function parseSignatureKey(value) {
  if (!/^sig=hwk;/.test(value || '')) throw new Error('unsupported_scheme');
  const params = {};
  for (const part of value.slice('sig=hwk;'.length).split(';')) {
    const match = /^\s*([a-z]+)="([A-Za-z0-9_-]+)"\s*$/.exec(part);
    if (!match || Object.hasOwn(params, match[1])) throw new Error('invalid_signature');
    params[match[1]] = match[2];
  }
  if (params.kty !== 'OKP' || params.crv !== 'Ed25519' || params.alg !== 'Ed25519' || !params.x || Object.keys(params).length !== 4) {
    throw new Error('unsupported_algorithm');
  }
  const x = Buffer.from(params.x, 'base64url');
  if (x.length !== 32 || x.toString('base64url') !== params.x) throw new Error('invalid_signature');
  return { jwk: { kty: params.kty, crv: params.crv, x: params.x, alg: params.alg }, value: value.trim() };
}

function verifyHttpSignature(req) {
  const digestHeader = req.get('content-digest') || '';
  const digestMatch = /^sha-256=:([A-Za-z0-9+/]+={0,2}):$/.exec(digestHeader);
  if (!digestMatch) throw new Error('invalid_signature');
  const rawBody = req.rawBody;
  if (!Buffer.isBuffer(rawBody)) throw new Error('invalid_request');
  const actualDigest = createHash('sha256').update(rawBody).digest();
  const providedDigest = Buffer.from(digestMatch[1], 'base64');
  if (providedDigest.length !== actualDigest.length || !actualDigest.equals(providedDigest)) throw new Error('invalid_signature');

  const { jwk, value: keyValue } = parseSignatureKey(req.get('signature-key') || '');
  const { components, created, signatureParams } = parseSignatureInput(req.get('signature-input'));
  if (!Number.isSafeInteger(created) || Math.abs(Math.floor(Date.now() / 1000) - created) > 300) throw new Error('invalid_signature');
  const signatureMatch = /^sig=:([A-Za-z0-9+/]+={0,2}):$/.exec(req.get('signature') || '');
  if (!signatureMatch) throw new Error('invalid_signature');

  const authority = (req.get('host') || '').toLowerCase();
  const path = new URL(req.originalUrl || req.url, `https://${authority}`).pathname;
  const values = {
    '@method': req.method,
    '@authority': authority,
    '@path': path,
    'content-digest': digestHeader.trim(),
    'signature-key': keyValue,
    cookie: req.get('cookie'),
  };
  const lines = components.map((component) => {
    if (values[component] === undefined) throw new Error('invalid_signature');
    return `"${component}": ${values[component]}`;
  });
  lines.push(`"@signature-params": ${signatureParams}`);
  const signature = Buffer.from(signatureMatch[1], 'base64');
  const publicKey = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, format: 'jwk' });
  if (!cryptoVerify(null, Buffer.from(lines.join('\n')), publicKey, signature)) throw new Error('invalid_signature');
  return jwk;
}

function validDomainHandle(handle) {
  return typeof handle === 'string' && handle.length <= 253 && HANDLE_RE.test(handle) && handle === handle.toLowerCase();
}

async function dnsDids(name, key) {
  if (name.length > 253) return [];
  try {
    const records = await resolveTxt(name);
    return records.map((chunks) => chunks.join('')).filter((value) => value.startsWith(`${key}=`)).map((value) => value.slice(key.length + 1));
  } catch (error) {
    if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') return [];
    throw error;
  }
}

async function wellKnownDid(handle, path, json) {
  const response = await axios.get(`https://${handle}${path}`, {
    timeout: 5000, responseType: 'text', transformResponse: [(value) => value], validateStatus: () => true,
  });
  if (response.status === 404 || response.status === 410) return null;
  if (response.status < 200 || response.status >= 300) throw new Error('Handle resolution failed.');
  const contentType = String(response.headers['content-type'] || '').toLowerCase();
  if (json) {
    if (!contentType.startsWith('application/json')) throw new Error('Handle resolution returned an invalid content type.');
    let document;
    try { document = JSON.parse(response.data); } catch { throw new Error('Handle resolution returned invalid JSON.'); }
    return typeof document.did === 'string' ? document.did : null;
  }
  if (!contentType.startsWith('text/plain')) throw new Error('Handle resolution returned an invalid content type.');
  return String(response.data || '').trim() || null;
}

async function resolveDomainHandle(handle) {
  const dns = await dnsDids(`_handle.${handle}`, 'did');
  const document = await wellKnownDid(handle, '/.well-known/handle', true);
  const currentDids = [...new Set([...dns, ...(document ? [document] : [])])];
  if (currentDids.length > 1) throw new Error('Handle resolution produced conflicting DIDs.');
  if (currentDids.length === 1) return currentDids[0];
  const atprotoDns = await dnsDids(`_atproto.${handle}`, 'did');
  const atprotoDocument = await wellKnownDid(handle, '/.well-known/atproto-did', false);
  const legacyDids = [...new Set([...atprotoDns, ...(atprotoDocument ? [atprotoDocument] : [])])];
  if (legacyDids.length !== 1) throw new Error(legacyDids.length ? 'Handle resolution produced conflicting DIDs.' : 'Handle does not resolve to a DID.');
  return legacyDids[0];
}

async function resolvePlcDid(did) {
  if (!/^did:plc:[a-z2-7]{24}$/.test(did)) throw new Error('Only did:plc accounts are supported by this PDS issuer.');
  const response = await axios.get(`${PLC_DIRECTORY}/${encodeURIComponent(did)}`, { timeout: 5000 });
  if (response.data?.id !== did) throw new Error('Resolved DID document did not match the DID.');
  return response.data;
}

async function validateResolvedHandle(handle, sub, issuer) {
  const did = await resolveDomainHandle(handle);
  if (did !== sub) throw new Error('Handle resolution did not match the requested account DID.');
  const document = await resolvePlcDid(sub);
  const backLink = (document.alsoKnownAs || [])
    .filter((value) => typeof value === 'string' && value.startsWith('at://'))
    .map((value) => value.slice(5).toLowerCase())
    .find((value) => validDomainHandle(value));
  if (backLink !== handle) throw new Error('DID document does not claim this handle.');
  const service = (document.service || []).find((item) => item.id === '#handle_verification');
  if (service?.type !== 'HandleVerification' || service.serviceEndpoint !== issuer) throw new Error('This issuer is not authorized by the account DID document.');
}

function signHvt(payload) {
  const jwk = getHvpPublicJwk();
  const header = { alg: 'Ed25519', kid: jwk.kid, typ: 'hvt+jwt' };
  const signingInput = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
  const signature = cryptoSign(null, Buffer.from(signingInput), hvpPrivateKey).toString('base64url');
  return `${signingInput}.${signature}~`;
}

router.get('/.well-known/handle-verification', (req, res) => {
  try {
    const issuer = issuerOrigin(req);
    getHvpPublicJwk();
    res.set('Cache-Control', 'public, max-age=3600');
    return res.json({ issuer, issuance_endpoint: `${issuer}/hvp/issuance`, jwks_uri: `${issuer}/hvp/jwks`, signing_alg_values_supported: ['Ed25519'], federations: ['https://atproto.com'] });
  } catch (error) {
    return errorResponse(res, 503, 'server_error', error.message);
  }
});

router.get('/hvp/jwks', (_req, res) => {
  try {
    res.set('Cache-Control', 'public, max-age=3600');
    return res.json({ keys: [getHvpPublicJwk()] });
  } catch (error) {
    return errorResponse(res, 503, 'server_error', error.message);
  }
});

router.post('/hvp/issuance', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (!/^application\/json(?:\s*;|$)/i.test(req.get('content-type') || '')) return errorResponse(res, 400, 'invalid_request', 'Content-Type must be application/json.');
  if (req.get('sec-fetch-dest') !== 'handle-verification') return errorResponse(res, 400, 'invalid_request', 'Sec-Fetch-Dest must be handle-verification.');
  let holderJwk;
  try { holderJwk = verifyHttpSignature(req); } catch (error) {
    const detail = ['unsupported_scheme', 'unsupported_algorithm'].includes(error.message) ? error.message : 'invalid_signature';
    res.set('Signature-Error', `error=${detail}`);
    if (detail === 'unsupported_algorithm') res.set('Accept-Signature-Alg', 'Ed25519');
    return errorResponse(res, 400, 'invalid_signature', detail === 'invalid_signature' ? 'HTTP Message Signature verification failed.' : 'Unsupported request signature scheme or algorithm.');
  }
  const { handle, sub } = req.body || {};
  if (!validDomainHandle(handle) || !/^did:(?:plc:[a-z2-7]{24}|web:.+)$/.test(sub || '')) return errorResponse(res, 400, 'invalid_request', 'A normalized domain handle and supported DID are required.');
  const user = req.user;
  const session = req.session;
  if (!session || session.did !== sub || String(session.handle).toLowerCase() !== handle || sub !== user.did || String(user.handle).toLowerCase() !== handle) {
    return errorResponse(res, 401, 'authentication_required', 'User must be authenticated and control the requested handle.');
  }
  try {
    const issuer = issuerOrigin(req);
    await validateResolvedHandle(handle, sub, issuer);
    const issuanceToken = signHvt({ iss: issuer, iat: Math.floor(Date.now() / 1000), cnf: { jwk: holderJwk }, handle, sub });
    return res.status(200).type('application/json').json({ issuance_token: issuanceToken });
  } catch (error) {
    if (/not authorized|does not resolve|resolution|claim this handle|match the requested account/i.test(error.message)) return errorResponse(res, 400, 'invalid_request', error.message);
    console.error('[HVP] Issuance failed:', error.message);
    return errorResponse(res, 500, 'server_error');
  }
});

export { getHvpPrivateKey, getHvpPublicJwk };
export default router;
