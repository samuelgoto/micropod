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
  const url = `https://${handle}${path}`;
  let response;
  try {
    response = await axios.get(url, {
      timeout: 5000, responseType: 'text', transformResponse: [(value) => value], validateStatus: () => true,
    });
  } catch (error) {
    if (error.code === 'ENOTFOUND') return { did: null, url, status: 'hostname not resolvable' };
    throw error;
  }
  if (response.status === 404 || response.status === 410) return { did: null, url, status: response.status };
  if (response.status < 200 || response.status >= 300) throw new Error('Handle resolution failed.');
  const contentType = String(response.headers['content-type'] || '').toLowerCase();
  if (json) {
    if (!contentType.startsWith('application/json')) throw new Error('Handle resolution returned an invalid content type.');
    let document;
    try { document = JSON.parse(response.data); } catch { throw new Error('Handle resolution returned invalid JSON.'); }
    return { did: typeof document.did === 'string' ? document.did : null, url, status: response.status, contentType };
  }
  if (!contentType.startsWith('text/plain')) throw new Error('Handle resolution returned an invalid content type.');
  return { did: String(response.data || '').trim() || null, url, status: response.status, contentType };
}

async function resolveDomainHandle(handle) {
  const diagnostics = [];
  const dnsName = `_handle.${handle}`;
  const dns = await dnsDids(dnsName, 'did');
  diagnostics.push({ source: 'DNS TXT', name: dnsName, dids: dns });
  const document = await wellKnownDid(handle, '/.well-known/handle', true);
  diagnostics.push({ source: 'HTTPS well-known', ...document });
  const currentDids = [...new Set([...dns, ...(document.did ? [document.did] : [])])];
  if (currentDids.length > 1) throw new Error('Handle resolution produced conflicting DIDs.');
  if (currentDids.length === 1) return { did: currentDids[0], diagnostics, method: dns.length ? 'DNS TXT _handle' : 'HTTPS /.well-known/handle' };
  const atprotoName = `_atproto.${handle}`;
  const atprotoDns = await dnsDids(atprotoName, 'did');
  diagnostics.push({ source: 'Legacy DNS TXT', name: atprotoName, dids: atprotoDns });
  const atprotoDocument = await wellKnownDid(handle, '/.well-known/atproto-did', false);
  diagnostics.push({ source: 'Legacy HTTPS well-known', ...atprotoDocument });
  const legacyDids = [...new Set([...atprotoDns, ...(atprotoDocument.did ? [atprotoDocument.did] : [])])];
  if (legacyDids.length !== 1) throw new Error(legacyDids.length ? 'Handle resolution produced conflicting DIDs.' : 'Handle does not resolve to a DID.');
  return { did: legacyDids[0], diagnostics, method: atprotoDns.length ? 'legacy DNS TXT _atproto' : 'legacy HTTPS /.well-known/atproto-did' };
}

async function validateResolvedHandle(handle, sub, issuer) {
  const resolution = await resolveDomainHandle(handle);
  if (resolution.did !== sub) throw new Error('Handle resolution did not match the requested account DID.');
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
  return {
    details: [
      ...resolution.diagnostics,
      { source: 'PLC DID document', url: `${PLC_DIRECTORY}/${encodeURIComponent(sub)}`, status: response.status, id: response.data.id },
      { source: 'DID back-link', expected: `at://${handle}`, found: `at://${backLink}`, matched: backLink === handle },
      { source: 'HandleVerification service', id: service.id, type: service.type, serviceEndpoint: service.serviceEndpoint, expectedEndpoint: issuer, matched: service.serviceEndpoint === issuer },
    ],
    method: resolution.method,
  };
}

function addStep(steps, name, summary, details) {
  steps.push({ name, ok: true, summary, details });
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
  addStep(steps, 'Issuer metadata', 'Issuer, issuance endpoint, and JWKS URL use the configured HTTPS origin; Ed25519 is advertised.', [
    { label: 'GET', value: `${issuer}/.well-known/handle-verification` },
    { label: 'HTTP status', value: metadataResponse.status },
    { label: 'issuer', value: metadata.issuer, matched: metadata.issuer === issuer },
    { label: 'issuance_endpoint', value: issuanceUrl.href, sameOrigin: issuanceUrl.origin === issuer },
    { label: 'jwks_uri', value: jwksUrl.href, sameOrigin: jwksUrl.origin === issuer },
    { label: 'signing_alg_values_supported', value: metadata.signing_alg_values_supported },
    { label: 'federations', value: metadata.federations || [] },
  ]);

  const jwksResponse = await http.get(jwksUrl.href);
  const keys = jwksResponse.data?.keys;
  if (!Array.isArray(keys) || !keys.length) throw new Error('Issuer JWKS did not contain any signing keys.');
  addStep(steps, 'Issuer JWKS', 'The issuer publishes at least one public signing key.', [
    { label: 'GET', value: jwksUrl.href },
    { label: 'HTTP status', value: jwksResponse.status },
    { label: 'keys', value: keys.map(({ kid, kty, crv, alg, use }) => ({ kid, kty, crv, alg, use })) },
  ]);

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
  const signatureHeader = `sig=:${holderSignature}:`;
  const holderRequestSignatureValid = cryptoVerify(null, Buffer.from(signatureBase), holderPublicKey, Buffer.from(holderSignature, 'base64'));
  if (!holderRequestSignatureValid) throw new Error('The generated holder request signature did not verify.');

  const issuanceHeaders = {
    host: issuanceUrl.host,
    'content-type': 'application/json',
    'sec-fetch-dest': 'handle-verification',
    'sec-fetch-site': 'same-origin',
    'content-digest': digest,
    'signature-input': signatureInput,
    signature: signatureHeader,
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
  addStep(steps, 'Holder request and issuance', 'The issuer accepted the holder request and authenticated session.', [
    { label: 'request', value: `POST ${issuanceUrl.href}` },
    { label: 'content-type', value: issuanceHeaders['content-type'] },
    { label: 'Sec-Fetch-Dest', value: issuanceHeaders['sec-fetch-dest'] },
    { label: 'session cookie', value: 'present (value redacted)' },
    { label: 'request body', value: JSON.parse(body) },
    { label: 'Content-Digest', value: digest },
    { label: 'Signature-Input', value: signatureInput },
    { label: 'Signature-Key', value: signatureKey },
    { label: 'Signature', value: signatureHeader },
    { label: 'signature base (cookie redacted)', value: signatureBase.replace(`"cookie": ${cookieHeader}`, '"cookie": [redacted]') },
    { label: 'signed components', value: ['@method', '@authority', '@path', 'content-digest', 'signature-key', 'cookie'] },
    { label: 'local holder signature check', value: holderRequestSignatureValid ? 'PASS' : 'FAIL' },
    { label: 'HTTP response status', value: issuanceResponse.status },
    { label: 'issuance token format', value: 'SD-JWT with trailing ~' },
    { label: 'HVT', value: issuanceToken },
  ]);

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
  addStep(steps, 'HVT signature and claims', 'The HVT signature verifies against the advertised issuer key, and its claims match this account and the simulated holder key.', [
    { label: 'HVT header', value: hvtHeader },
    { label: 'HVT claims', value: hvtPayload },
    { label: 'JWKS key selected', value: { kid: signingKey.kid, kty: signingKey.kty, crv: signingKey.crv, alg: signingKey.alg } },
    { label: 'issuer signature', value: 'PASS (Ed25519)' },
    { label: 'iss matches configured issuer', value: hvtPayload.iss === issuer },
    { label: 'handle matches account', value: hvtPayload.handle === handle },
    { label: 'sub matches account DID', value: hvtPayload.sub === did },
    { label: 'iat within 300 seconds', value: true },
    { label: 'cnf.jwk matches generated holder key', value: true },
    { label: 'simulated holder public JWK', value: holderJwk },
    { label: 'HVT', value: issuanceToken },
  ]);

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
  const kbChecks = {
    algorithmMatchesConfirmationKey: kb.header.alg === hvtPayload.cnf.jwk.alg,
    typeIsKeyBindingJwt: kb.header.typ === 'kb+jwt',
    audienceMatchesVerifier: kb.payload.aud === verifierOrigin,
    nonceMatches: kb.payload.nonce === nonce,
    sdHashMatchesHvt: kb.payload.sd_hash === expectedSdHash,
    issueTimeWithin300Seconds: Math.abs(Date.now() / 1000 - kb.payload.iat) <= 300,
    holderSignatureValid: cryptoVerify(null, kb.signingInput, holderVerifyKey, kb.signature),
  };
  if (Object.values(kbChecks).some((passed) => !passed)) {
    throw new Error('Simulated verifier rejected the holder key-binding JWT.');
  }
  const hvtKbToken = `${issuanceToken}${kbInput}.${kbSignature}`;
  addStep(steps, 'HVT+KB holder proof', 'The simulated verifier accepts the key-binding JWT for this HVT.', [
    { label: 'KB-JWT header', value: kb.header },
    { label: 'KB-JWT claims', value: kb.payload },
    { label: 'verification checks', value: kbChecks },
    { label: 'sd_hash expected', value: expectedSdHash },
    { label: 'sd_hash actual', value: kb.payload.sd_hash },
    { label: 'HVT+KB', value: hvtKbToken },
  ]);

  const resolution = await validateResolvedHandle(handle, did, issuer);
  addStep(steps, 'Verifier handle resolution', `The handle resolves to the account DID through ${resolution.method}; the DID back-link and issuer service match.`, resolution.details.map((entry) => ({ label: entry.source, value: entry })));
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

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

function formatDetail(value) {
  if (typeof value === 'string') return value;
  return JSON.stringify(value, null, 2);
}

export function renderHvpSelfCheckHtml({ success, handle, did, issuer, steps = [], error = '' }) {
  const resultMarkup = steps.map((step) => `
    <section class="step ${step.ok ? 'pass' : 'fail'}">
      <h2><span>${step.ok ? 'PASS' : 'FAIL'}</span> ${escapeHtml(step.name)}</h2>
      <p>${escapeHtml(step.summary || step.detail || '')}</p>
      ${step.details?.length ? `<dl>${step.details.map(({ label, value }) => `
        <dt>${escapeHtml(label)}</dt><dd><pre>${escapeHtml(formatDetail(value))}</pre></dd>
      `).join('')}</dl>` : ''}
    </section>`).join('');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Handle Verification Self-Check</title>
  <style>
    :root { color-scheme: light dark; font: 16px/1.5 system-ui, sans-serif; }
    body { max-width: 960px; margin: 2rem auto; padding: 0 1rem 3rem; }
    h1 { margin-bottom: .25rem; }
    .identity, .summary { color: #777; overflow-wrap: anywhere; }
    .step { margin: 1rem 0; padding: 1rem 1.25rem; border: 1px solid #7776; border-radius: .75rem; }
    .step h2 { margin: 0; font-size: 1.15rem; }
    .pass h2 span { color: #17803d; } .fail h2 span, .error { color: #c33; }
    dl { display: grid; grid-template-columns: minmax(150px, 220px) minmax(0, 1fr); gap: .5rem 1rem; }
    dt { font-weight: 650; } dd { margin: 0; min-width: 0; }
    pre { margin: 0; padding: .65rem; white-space: pre-wrap; overflow-wrap: anywhere; background: #7771; border-radius: .35rem; }
    .actions { margin-top: 2rem; }
    a { color: inherit; }
    @media (max-width: 600px) { dl { grid-template-columns: 1fr; gap: .15rem; } dd { margin-bottom: .65rem; } }
  </style>
</head>
<body>
  <h1>Handle Verification Self-Check</h1>
  <p class="identity">Handle: <strong>${escapeHtml(handle || 'unknown')}</strong><br>DID: <code>${escapeHtml(did || 'unknown')}</code><br>Issuer: <code>${escapeHtml(issuer || 'unknown')}</code></p>
  <h2 class="${success ? 'pass' : 'error'}">${success ? 'All checks passed' : 'Self-check failed'}</h2>
  ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
  ${resultMarkup || '<p>No verification steps completed.</p>'}
  <p class="summary">The report includes the simulated HVT and HVT+KB tokens. It redacts the session cookie and never includes the holder private key.</p>
  <div class="actions"><a href="/">Return to admin dashboard</a></div>
</body>
</html>`;
}
