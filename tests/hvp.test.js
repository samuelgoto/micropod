import { jest } from '@jest/globals';
import http from 'http';
import axios from 'axios';
import nock from 'nock';
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from 'crypto';
import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import app from '../src/server.js';
import { getHvpPrivateKey, getHvpPublicJwk } from '../src/hvp.js';
import { db, setUpForTesting, create } from '../src/db.js';
import { setUpRepo } from '../src/repo.js';
import { createSession } from '../src/session.js';
import { sequencer } from '../src/sequencer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HANDLE = 'identity.test';
const DID = 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa';
const PASSWORD = 'hvp-test-password';

describe('Handle Verification issuer', () => {
  let server;
  let baseUrl;
  let dbPath;
  let cookie;

  beforeAll(async () => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    process.env.HANDLE = HANDLE;
    process.env.PDS_DID = DID;
    process.env.DOMAIN = 'issuer.test';
    process.env.PASSWORD = PASSWORD;
    dbPath = path.join(__dirname, `hvp-${Date.now()}.db`);
    await setUpForTesting(`file:${dbPath}`);
    await create();
    await setUpRepo();
    const session = await createSession({ did: DID, handle: HANDLE });
    cookie = `pds_session=${session.sessionId}`;

    server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  }, 30000);

  afterEach(() => nock.cleanAll());

  afterAll(async () => {
    sequencer.close();
    db.close();
    await new Promise((resolve) => server.close(resolve));
    for (const file of [dbPath, `${dbPath}-shm`, `${dbPath}-wal`]) {
      if (fs.existsSync(file)) fs.unlinkSync(file);
    }
    jest.restoreAllMocks();
  });

  function signedRequest(body, { session = true, created = Math.floor(Date.now() / 1000), corruptDigest = false } = {}) {
    const rawBody = JSON.stringify(body);
    const digest = createHash('sha256').update(rawBody).digest('base64');
    const digestHeader = `sha-256=:${corruptDigest ? Buffer.alloc(32).toString('base64') : digest}:`;
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const publicJwk = publicKey.export({ format: 'jwk' });
    const signatureKey = `sig=hwk;kty="OKP";crv="Ed25519";x="${publicJwk.x}";alg="Ed25519"`;
    const signatureInput = `sig=("@method" "@authority" "@path" "content-digest" "signature-key");created=${created}`;
    const authority = new URL(baseUrl).host.toLowerCase();
    const signatureBase = [
      '"@method": POST',
      `"@authority": ${authority}`,
      '"@path": /hvp/issuance',
      `"content-digest": ${digestHeader}`,
      `"signature-key": ${signatureKey}`,
      `"@signature-params": ${signatureInput.slice(4)}`,
    ].join('\n');
    const signature = sign(null, Buffer.from(signatureBase), privateKey).toString('base64');
    return {
      data: rawBody,
      headers: {
        'Content-Type': 'application/json',
        'Sec-Fetch-Dest': 'handle-verification',
        'Content-Digest': digestHeader,
        'Signature-Input': signatureInput,
        'Signature': `sig=:${signature}:`,
        'Signature-Key': signatureKey,
        ...(session ? { Cookie: cookie } : {}),
      },
      validateStatus: () => true,
    };
  }

  function mockHandleAndDid({ issuer = 'https://issuer.test', handleDid = DID, backLink = `at://${HANDLE}` } = {}) {
    nock(`https://${HANDLE}`)
      .get('/.well-known/handle')
      .reply(404)
      .get('/.well-known/atproto-did')
      .reply(200, handleDid, { 'Content-Type': 'text/plain' });
    nock('https://plc.directory')
      .get(`/${encodeURIComponent(DID)}`)
      .reply(200, {
        id: DID,
        alsoKnownAs: [backLink],
        service: [{ id: '#handle_verification', type: 'HandleVerification', serviceEndpoint: issuer }],
      });
  }

  test('keeps one ephemeral signing key for the process and rotates it in a fresh process', () => {
    const publicJwk = getHvpPublicJwk();
    expect(getHvpPublicJwk()).toBe(publicJwk);
    expect(getHvpPrivateKey()).toBe(getHvpPrivateKey());

    const childSource = "import('./src/hvp.js').then((m) => process.stdout.write(m.getHvpPublicJwk().kid))";
    const kid1 = execFileSync(process.execPath, ['--input-type=module', '-e', childSource], { cwd: process.cwd(), encoding: 'utf8' });
    const kid2 = execFileSync(process.execPath, ['--input-type=module', '-e', childSource], { cwd: process.cwd(), encoding: 'utf8' });
    expect(kid1).not.toBe(kid2);
  });

  test('publishes HVP metadata and the matching ephemeral Ed25519 JWKS key', async () => {
    const metadata = await axios.get(`${baseUrl}/.well-known/handle-verification`);
    expect(metadata.data).toEqual({
      issuer: 'https://issuer.test',
      issuance_endpoint: 'https://issuer.test/hvp/issuance',
      jwks_uri: 'https://issuer.test/hvp/jwks',
      signing_alg_values_supported: ['Ed25519'],
      federations: ['https://atproto.com'],
    });

    const jwks = await axios.get(`${baseUrl}/hvp/jwks`);
    expect(jwks.data.keys).toHaveLength(1);
    expect(jwks.data.keys[0]).toMatchObject({ kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519' });
    expect(jwks.data.keys[0].kid).toBe(getHvpPublicJwk().kid);
  });

  test('requires the HVP fetch destination and a valid signed request', async () => {
    const missingDestination = signedRequest({ handle: HANDLE, sub: DID });
    delete missingDestination.headers['Sec-Fetch-Dest'];
    const badDestination = await axios.post(`${baseUrl}/hvp/issuance`, missingDestination.data, missingDestination);
    expect(badDestination.status).toBe(400);
    expect(badDestination.data.error).toBe('invalid_request');

    const stale = signedRequest({ handle: HANDLE, sub: DID }, { created: 1 });
    const staleSignature = await axios.post(`${baseUrl}/hvp/issuance`, stale.data, stale);
    expect(staleSignature.status).toBe(400);
    expect(staleSignature.data.error).toBe('invalid_signature');
    expect(staleSignature.headers['signature-error']).toBe('error=invalid_signature');

    const digest = signedRequest({ handle: HANDLE, sub: DID }, { corruptDigest: true });
    const badDigest = await axios.post(`${baseUrl}/hvp/issuance`, digest.data, digest);
    expect(badDigest.status).toBe(400);
    expect(badDigest.data.error).toBe('invalid_signature');
  });

  test('requires a session for the same handle and DID', async () => {
    const request = signedRequest({ handle: HANDLE, sub: DID }, { session: false });
    const response = await axios.post(`${baseUrl}/hvp/issuance`, request.data, request);
    expect(response.status).toBe(401);
    expect(response.data.error).toBe('authentication_required');
  });

  test('issues a key-bound HVT only when handle resolution and PLC authorization agree', async () => {
    mockHandleAndDid();
    const request = signedRequest({ handle: HANDLE, sub: DID });
    const response = await axios.post(`${baseUrl}/hvp/issuance`, request.data, request);
    expect(response.status).toBe(200);
    expect(typeof response.data.issuance_token).toBe('string');
    expect(response.data.issuance_token.endsWith('~')).toBe(true);

    const jwt = response.data.issuance_token.slice(0, -1);
    const [headerPart, payloadPart, signaturePart] = jwt.split('.');
    const header = JSON.parse(Buffer.from(headerPart, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString());
    const jwk = getHvpPublicJwk();
    expect(header).toEqual({ alg: 'Ed25519', kid: jwk.kid, typ: 'hvt+jwt' });
    expect(payload).toMatchObject({ iss: 'https://issuer.test', handle: HANDLE, sub: DID, cnf: { jwk: expect.objectContaining({ kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519' }) } });
    const signingInput = Buffer.from(`${headerPart}.${payloadPart}`);
    const verifyKey = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, format: 'jwk' });
    expect(verify(null, signingInput, verifyKey, Buffer.from(signaturePart, 'base64url'))).toBe(true);
  });

  test('refuses to issue when the PLC DID document does not authorize this issuer', async () => {
    mockHandleAndDid({ issuer: 'https://other-issuer.test' });
    const request = signedRequest({ handle: HANDLE, sub: DID });
    const response = await axios.post(`${baseUrl}/hvp/issuance`, request.data, request);
    expect(response.status).toBe(400);
    expect(response.data.error).toBe('invalid_request');
  });
});
