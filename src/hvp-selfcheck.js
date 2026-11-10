import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign as cryptoSign, verify as cryptoVerify } from 'crypto';
import { resolveTxt } from 'dns/promises';
import axios from 'axios';

const PLC_DIRECTORY = 'https://plc.directory';
const HANDLE_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;

function getIssuerOrigin(req) {
  try {
    const configured = process.env.DOMAIN;
    if (!configured) return '';
    const candidate = configured.includes('://') ? configured : `https://${configured}`;
    return new URL(candidate).origin;
  } catch {
    return '';
  }
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
  let response;
  try {
    response = await axios.get(`https://${handle}${path}`, {
      timeout: 5000, responseType: 'text', transformResponse: [(value) => value], validateStatus: () => true,
    });
  } catch (error) {
    if (error.code === 'ENOTFOUND') return null;
    throw error;
  }
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

async function validateResolvedHandle(handle, sub, issuer) {
  const did = await resolveDomainHandle(handle);
  if (did !== sub) throw new Error('Handle resolution did not match the requested account DID.');
  if (!/^did:plc:[a-z2-7]{24}$/.test(sub)) throw new Error('Only did:plc accounts are supported by this PDS issuer.');
  const response = await axios.get(`${PLC_DIRECTORY}/${encodeURIComponent(sub)}`, { timeout: 5000 });
  if (response.data?.id !== sub) throw new Error('Resolved DID document did not match the DID.');
  const backLink = (response.data.alsoKnownAs || [])
    .filter((value) => typeof value === 'string' && value.startsWith('at://'))
    .map((value) => value.slice(5).toLowerCase())
    .find((value) => validDomainHandle(value));
  if (backLink !== handle) throw new Error('DID document does not claim this handle.');
  const service = (response.data.service || []).find((item) => item.id === '#handle_verification');
  if (service?.type !== 'HandleVerification' || service.serviceEndpoint !== issuer) throw new Error('This issuer is not authorized by the account DID document.');
}

async function runLiveHvpSelfCheck(req, steps) {
  const issuer = getIssuerOrigin(req);
  if (!issuer || !issuer.startsWith('https://')) {
    throw new Error('DOMAIN must identify the live HTTPS issuer origin before this check can run.');
  }
  const handle = String(req.user.handle).toLowerCase();
  const did = req.user.did;
  const http = axios.create({ timeout: 10000, maxRedirects: 0 });

  const metadataResponse = await http.get(`${issuer}/.well-known/handle-verification`);
  const metadata = metadataResponse.data;
  const issuanceUrl = new URL(metadata?.issuance_endpoint || '');
  const jwksUrl = new URL(metadata?.jwks_uri || '');
  if (metadata?.issuer !== issuer || issuanceUrl.protocol !== 'https:' || issuanceUrl.origin !== issuer || jwksUrl.protocol !== 'https:' || jwksUrl.origin !== issuer) {
    throw new Error('Issuer metadata has a mismatched issuer or non-same-origin HTTPS endpoint.');
  }
  if (!Array.isArray(metadata.signing_alg_values_supported) || !metadata.signing_alg_values_supported.includes('Ed25519')) {
    throw new Error('Issuer metadata does not advertise Ed25519 support.');
  }
  steps.push({ name: 'Issuer metadata', ok: true, detail: 'Issuer and HTTPS endpoint origins match.' });

  const jwksResponse = await http.get(jwksUrl.href);
  const keys = jwksResponse.data?.keys;
  if (!Array.isArray(keys) || !keys.length) throw new Error('Issuer JWKS did not contain any signing keys.');
  steps.push({ name: 'Issuer JWKS', ok: true, detail: `${keys.length} public signing key(s) published.` });

  const { privateKey: holderPrivateKey, publicKey: holderPublicKey } = generateKeyPairSync('ed25519');
  const exportedHolderKey = holderPublicKey.export({ format: 'jwk' });
  const holderJwk = { kty: 'OKP', crv: 'Ed25519', x: exportedHolderKey.x, alg: 'Ed25519' };
  const signatureKey = `sig=hwk;kty="OKP";crv="Ed25519";x="${holderJwk.x}";alg="Ed25519"`;
  const body = JSON.stringify({ handle, sub: did });
  const digest = `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
  const created = Math.floor(Date.now() / 1000);
  const sessionId = req.session?.id;
  if (!sessionId) throw new Error('The dashboard session is missing.');
  const cookieHeader = `pds_session=${encodeURIComponent(sessionId)}`;
  const signatureInput = `sig=("@method" "@authority" "@path" "content-digest" "signature-key" "cookie");created=${created}`;
  const signatureBase = [
    '"@method": POST',
    `"@authority": ${issuanceUrl.host.toLowerCase()}`,
    `"@path": ${issuanceUrl.pathname}`,
    `"content-digest": ${digest}`,
    `"signature-key": ${signatureKey}`,
    `"cookie": ${cookieHeader}`,
    `"@signature-params": ${signatureInput.slice(4)}`,
  ].join('\n');
  const holderSignature = cryptoSign(null, Buffer.from(signatureBase), holderPrivateKey).toString('base64');

  const issuanceHeaders = {
    host: issuanceUrl.host,
    'content-type': 'application/json',
    'sec-fetch-dest': 'handle-verification',
    'sec-fetch-site': 'same-origin',
    'content-digest': digest,
    'signature-input': signatureInput,
    signature: `sig=:${holderSignature}:`,
    'signature-key': signatureKey,
    cookie: cookieHeader,
  };
  let issuanceResponse;
  try {
    issuanceResponse = await http.post(issuanceUrl.href, body, { headers: issuanceHeaders });
  } catch (error) {
    const detail = error.response?.data?.error_description || error.response?.data?.error || error.message;
    throw new Error(`The issuance endpoint returned HTTP ${error.response?.status || 'error'}: ${detail}`);
  }
  const issuanceToken = issuanceResponse.data?.issuance_token;
  if (typeof issuanceToken !== 'string' || !issuanceToken.endsWith('~')) {
    throw new Error('The issuance endpoint did not return an HVT in the expected SD-JWT format.');
  }
  steps.push({ name: 'Holder request and issuance', ok: true, detail: 'The live endpoint accepted the signed holder request and session cookie.' });

  const hvtParts = issuanceToken.slice(0, -1).split('.');
  if (hvtParts.length !== 3) throw new Error('The issuer returned a malformed HVT.');
  let hvtHeader;
  let hvtPayload;
  try {
    hvtHeader = JSON.parse(Buffer.from(hvtParts[0], 'base64url').toString());
    hvtPayload = JSON.parse(Buffer.from(hvtParts[1], 'base64url').toString());
  } catch {
    throw new Error('The issuer returned malformed HVT claims.');
  }
  const signingKey = keys.find((key) => key.kid === hvtHeader.kid);
  if (!signingKey || signingKey.kty !== 'OKP' || signingKey.crv !== 'Ed25519' || signingKey.alg !== 'Ed25519' || hvtHeader.alg !== 'Ed25519' || hvtHeader.typ !== 'hvt+jwt') {
    throw new Error('HVT header does not match an advertised Ed25519 JWKS key.');
  }
  const issuerPublicKey = createPublicKey({ key: { kty: signingKey.kty, crv: signingKey.crv, x: signingKey.x }, format: 'jwk' });
  const issuerSignature = Buffer.from(hvtParts[2], 'base64url');
  if (!cryptoVerify(null, Buffer.from(`${hvtParts[0]}.${hvtParts[1]}`), issuerPublicKey, issuerSignature)) {
    throw new Error('HVT signature did not verify against the issuer JWKS.');
  }
  if (hvtPayload.iss !== issuer || hvtPayload.handle !== handle || hvtPayload.sub !== did || !Number.isSafeInteger(hvtPayload.iat) || Math.abs(Date.now() / 1000 - hvtPayload.iat) > 300) {
    throw new Error('HVT claims do not match the configured issuer, handle, DID, or acceptable issue time.');
  }
  if (!hvtPayload.cnf?.jwk || ['kty', 'crv', 'x', 'alg'].some((name) => hvtPayload.cnf.jwk[name] !== holderJwk[name])) {
    throw new Error('HVT confirmation key does not match the simulated holder key.');
  }
  steps.push({ name: 'HVT signature and claims', ok: true, detail: 'Issuer signature, handle, DID, issue time, and holder key verified.' });

  const verifierOrigin = 'https://hvp-self-check.invalid';
  const nonce = randomBytes(16).toString('base64url');
  const kbPayload = {
    aud: verifierOrigin,
    nonce,
    iat: Math.floor(Date.now() / 1000),
    sd_hash: createHash('sha256').update(issuanceToken).digest('base64url'),
  };
  const kbHeader = { alg: holderJwk.alg, typ: 'kb+jwt' };
  const kbInput = `${Buffer.from(JSON.stringify(kbHeader)).toString('base64url')}.${Buffer.from(JSON.stringify(kbPayload)).toString('base64url')}`;
  const kbSignature = cryptoSign(null, Buffer.from(kbInput), holderPrivateKey).toString('base64url');
  const presented = `${issuanceToken.slice(0, -1)}~${kbInput}.${kbSignature}`;
  const [presentedHvt, presentedKb] = presented.split('~');
  const kbParts = presentedKb.split('.');
  const kb = {
    header: JSON.parse(Buffer.from(kbParts[0], 'base64url').toString()),
    payload: JSON.parse(Buffer.from(kbParts[1], 'base64url').toString()),
    signingInput: Buffer.from(`${kbParts[0]}.${kbParts[1]}`),
    signature: Buffer.from(kbParts[2], 'base64url'),
  };
  const holderVerifyKey = createPublicKey({ key: { kty: holderJwk.kty, crv: holderJwk.crv, x: holderJwk.x }, format: 'jwk' });
  const expectedSdHash = createHash('sha256').update(`${presentedHvt}~`).digest('base64url');
  if (kb.header.alg !== hvtPayload.cnf.jwk.alg || kb.header.typ !== 'kb+jwt' || kb.payload.aud !== verifierOrigin || kb.payload.nonce !== nonce || kb.payload.sd_hash !== expectedSdHash || Math.abs(Date.now() / 1000 - kb.payload.iat) > 300 || !cryptoVerify(null, kb.signingInput, holderVerifyKey, kb.signature)) {
    throw new Error('Simulated verifier rejected the holder key-binding JWT.');
  }
  steps.push({ name: 'HVT+KB holder proof', ok: true, detail: 'Verifier audience, nonce, HVT hash, and holder signature verified.' });

  await validateResolvedHandle(handle, did, issuer);
  steps.push({ name: 'Verifier handle resolution', ok: true, detail: 'Live handle resolution, DID back-link, and authorized issuer service agree.' });
}

export async function runHvpSelfCheck(req) {
  const steps = [];
  const issuer = getIssuerOrigin(req);
  try {
    await runLiveHvpSelfCheck(req, steps);
    return { handle: String(req.user.handle).toLowerCase(), did: req.user.did, issuer, steps };
  } catch (error) {
    error.steps = steps;
    throw error;
  }
}
