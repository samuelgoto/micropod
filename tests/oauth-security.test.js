import 'dotenv/config';
import { jest } from '@jest/globals';
import http from 'http';
import axios from 'axios';
import nock from 'nock';
import jwt from 'jsonwebtoken';
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'crypto';
import app from '../src/server.js';
import { db, setUpForTesting, create } from '../src/db.js';
import { setUpRepo } from '../src/repo.js';
import { sequencer } from '../src/sequencer.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = 3013;
const HOST = `http://localhost:${PORT}`;
const PASSWORD = 'oauth-security-pass';

const CLIENT_ID = 'https://good-client.example/meta.json';
const REDIRECT_URI = 'https://good-client.example/callback';
const EVIL_CLIENT_ID = 'https://evil.example/client-metadata.json';
const EVIL_REDIRECT = 'https://evil.example/callback';
const XSS_CLIENT_ID = 'https://xss-client.example/meta.json';
const XSS_REDIRECT = 'https://xss-client.example/callback';

const pkce = () => {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
};

const dpopKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const dpopFor = (htm, htu) => jwt.sign(
  { htm, htu, jti: randomUUID(), iat: Math.floor(Date.now() / 1000) },
  dpopKeys.privateKey,
  { algorithm: 'ES256', header: { typ: 'dpop+jwt', alg: 'ES256', jwk: dpopKeys.publicKey.export({ format: 'jwk' }) } }
);

const form = (obj) => new URLSearchParams(obj).toString();
const noRedirect = { maxRedirects: 0, validateStatus: () => true };

describe('OAuth authorization security', () => {
  let server;
  let dbPath;
  let cookie;

  beforeAll(async () => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    process.env.PASSWORD = PASSWORD;
    process.env.HANDLE = 'localhost.test';
    dbPath = path.join(__dirname, `oauth-security-${Date.now()}.db`);
    await setUpForTesting(`file:${dbPath}`); await create(); await setUpRepo();

    nock('https://good-client.example').persist().get('/meta.json').reply(200, {
      client_id: CLIENT_ID,
      client_name: 'Good Client',
      redirect_uris: [REDIRECT_URI],
      token_endpoint_auth_method: 'none',
      dpop_bound_access_tokens: true,
    });
    // Attacker-controlled metadata with HTML/JS payloads in every rendered field.
    nock('https://xss-client.example').persist().get('/meta.json').reply(200, {
      client_id: XSS_CLIENT_ID,
      client_name: '<img src=x onerror=alert(1)>',
      logo_uri: 'javascript:alert(2)',
      client_uri: 'javascript:alert(3)',
      policy_uri: '"><script>alert(4)</script>',
      redirect_uris: [XSS_REDIRECT, 'javascript:alert(5)'],
      scope_descriptions: { evil: '<script>alert(6)</script>' },
    });
    // evil.example has no metadata at all.
    nock('https://evil.example').persist().get(/.*/).reply(404);

    server = http.createServer(app);
    await new Promise((resolve) => server.listen(PORT, resolve));

    const login = await axios.post(`${HOST}/login`, form({ password: PASSWORD }), noRedirect);
    cookie = login.headers['set-cookie'][0].split(';')[0];
  });

  afterAll(async () => {
    nock.cleanAll();
    sequencer.close();
    db.close();
    await new Promise((resolve) => server.close(resolve));
    for (const p of [dbPath, `${dbPath}-shm`, `${dbPath}-wal`]) {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
  });

  const getConsentPage = async (params) => axios.get(`${HOST}/oauth/authorize`, {
    params, headers: { Cookie: cookie }, ...noRedirect,
  });

  describe('CSRF on POST /oauth/authorize', () => {
    test('cross-site approval using only the browser session is rejected (the PoC attack)', async () => {
      const { challenge } = pkce();
      const res = await axios.post(`${HOST}/oauth/authorize`, form({
        client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: 'atproto', state: 'x',
        code_challenge: challenge, code_challenge_method: 'S256',
      }), { headers: { Cookie: cookie, Origin: 'https://evil.example', Referer: 'https://evil.example/' }, ...noRedirect });
      expect(res.status).toBe(403);
      expect(res.headers.location).toBeUndefined();
    });

    test('same-origin approval without the CSRF token is rejected', async () => {
      const { challenge } = pkce();
      const res = await axios.post(`${HOST}/oauth/authorize`, form({
        client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: 'atproto',
        code_challenge: challenge, code_challenge_method: 'S256',
      }), { headers: { Cookie: cookie, Origin: HOST }, ...noRedirect });
      expect(res.status).toBe(403);
    });

    test('approval with a forged CSRF token is rejected', async () => {
      const { challenge } = pkce();
      const res = await axios.post(`${HOST}/oauth/authorize`, form({
        client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: 'atproto',
        code_challenge: challenge, code_challenge_method: 'S256', csrf_token: 'forged',
      }), { headers: { Cookie: cookie, Origin: HOST }, ...noRedirect });
      expect(res.status).toBe(403);
    });

    test('approval from our own consent page (same origin + CSRF token) succeeds', async () => {
      const { challenge } = pkce();
      const page = await getConsentPage({
        client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: 'atproto', state: 's1',
        code_challenge: challenge, code_challenge_method: 'S256',
      });
      expect(page.status).toBe(200);
      const csrf = page.data.match(/name="csrf_token" value="([^"]+)"/)?.[1];
      expect(csrf).toBeTruthy();

      const res = await axios.post(`${HOST}/oauth/authorize`, form({
        csrf_token: csrf, client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: 'atproto', state: 's1',
        code_challenge: challenge, code_challenge_method: 'S256',
      }), { headers: { Cookie: cookie, Origin: HOST }, ...noRedirect });
      expect(res.status).toBe(302);
      const location = new URL(res.headers.location);
      expect(location.origin + location.pathname).toBe(REDIRECT_URI);
      expect(location.searchParams.get('code')).toBeTruthy();
      expect(location.searchParams.get('state')).toBe('s1');
    });
  });

  describe('client / redirect validation fails closed', () => {
    test('unknown client (metadata unavailable) never gets a code, even with the password', async () => {
      const { challenge } = pkce();
      const res = await axios.post(`${HOST}/oauth/authorize`, form({
        client_id: EVIL_CLIENT_ID, redirect_uri: EVIL_REDIRECT, scope: 'atproto',
        code_challenge: challenge, code_challenge_method: 'S256', password: PASSWORD,
      }), noRedirect);
      expect(res.status).toBe(400);
      expect(res.headers.location).toBeUndefined();
    });

    test('unregistered redirect_uri for a real client is rejected', async () => {
      const { challenge } = pkce();
      const res = await axios.post(`${HOST}/oauth/authorize`, form({
        client_id: CLIENT_ID, redirect_uri: EVIL_REDIRECT, scope: 'atproto',
        code_challenge: challenge, code_challenge_method: 'S256', password: PASSWORD,
      }), noRedirect);
      expect(res.status).toBe(400);
      expect(res.headers.location).toBeUndefined();
    });

    test('missing redirect_uri is rejected', async () => {
      const { challenge } = pkce();
      const res = await axios.post(`${HOST}/oauth/authorize`, form({
        client_id: CLIENT_ID, scope: 'atproto',
        code_challenge: challenge, code_challenge_method: 'S256', password: PASSWORD,
      }), noRedirect);
      expect(res.status).toBe(400);
    });

    test('javascript: redirect_uri is rejected even if the client registers it', async () => {
      const { challenge } = pkce();
      const res = await axios.post(`${HOST}/oauth/authorize`, form({
        client_id: XSS_CLIENT_ID, redirect_uri: 'javascript:alert(5)', scope: 'atproto',
        code_challenge: challenge, code_challenge_method: 'S256', password: PASSWORD,
      }), noRedirect);
      expect(res.status).toBe(400);
    });

    test('PKCE S256 is required', async () => {
      for (const extra of [{}, { code_challenge: pkce().challenge, code_challenge_method: 'plain' }]) {
        const res = await axios.post(`${HOST}/oauth/authorize`, form({
          client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: 'atproto', password: PASSWORD, ...extra,
        }), noRedirect);
        expect(res.status).toBe(400);
      }
    });

    test('PAR rejects invalid clients', async () => {
      const res = await axios.post(`${HOST}/oauth/par`, form({
        client_id: EVIL_CLIENT_ID, redirect_uri: EVIL_REDIRECT, code_challenge: pkce().challenge, code_challenge_method: 'S256',
      }), { validateStatus: () => true });
      expect(res.status).toBe(400);
    });
  });

  describe('XSS on GET /oauth/authorize', () => {
    test('a bogus client_id is not reflected into an HTML page', async () => {
      const payload = 'https://x.example/"><script>alert(1)</script>';
      const res = await getConsentPage({ client_id: payload, redirect_uri: 'https://x.example/cb', state: '"><script>alert(2)</script>' });
      expect(res.status).toBe(400);
      expect(res.headers['content-type']).toMatch(/text\/plain/);
      expect(String(res.data)).not.toContain('<script>');
    });

    test('attacker-controlled metadata and params are escaped / neutralized', async () => {
      const res = await getConsentPage({
        client_id: XSS_CLIENT_ID, redirect_uri: XSS_REDIRECT,
        scope: 'atproto include:evil repo?collection=<b>x</b>',
        state: '"><script>alert(7)</script>',
        code_challenge: pkce().challenge, code_challenge_method: 'S256',
      });
      expect(res.status).toBe(200);
      const html = res.data;
      expect(html).not.toContain('<script>');
      expect(html).not.toContain('<img src=x');
      expect(html).not.toContain('<b>x</b>');
      expect(html).not.toMatch(/(href|src)="javascript:/i);
      expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    });

    test('missing client_id returns 400 instead of crashing', async () => {
      const res = await getConsentPage({});
      expect(res.status).toBe(400);
    });
  });

  describe('token endpoint', () => {
    const getCode = async (challenge) => {
      const res = await axios.post(`${HOST}/oauth/authorize`, form({
        client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: 'atproto',
        code_challenge: challenge, code_challenge_method: 'S256', password: PASSWORD,
      }), noRedirect);
      expect(res.status).toBe(302);
      return new URL(res.headers.location).searchParams.get('code');
    };

    test('DPoP is required to redeem an authorization code', async () => {
      const { verifier, challenge } = pkce();
      const code = await getCode(challenge);
      const res = await axios.post(`${HOST}/oauth/token`, form({
        grant_type: 'authorization_code', code, code_verifier: verifier, client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
      }), { validateStatus: () => true });
      expect(res.status).toBe(400);
      expect(res.data.error).toBe('invalid_dpop_proof');
    });

    test('redirect_uri must match the one used at authorization', async () => {
      const { verifier, challenge } = pkce();
      const code = await getCode(challenge);
      const res = await axios.post(`${HOST}/oauth/token`, form({
        grant_type: 'authorization_code', code, code_verifier: verifier, client_id: CLIENT_ID, redirect_uri: 'https://good-client.example/other',
      }), { headers: { DPoP: dpopFor('POST', `${HOST}/oauth/token`) }, validateStatus: () => true });
      expect(res.status).toBe(400);
      expect(res.data.error).toBe('invalid_grant');
    });

    test('a legitimate PKCE + DPoP exchange still works', async () => {
      const { verifier, challenge } = pkce();
      const code = await getCode(challenge);
      const res = await axios.post(`${HOST}/oauth/token`, form({
        grant_type: 'authorization_code', code, code_verifier: verifier, client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
      }), { headers: { DPoP: dpopFor('POST', `${HOST}/oauth/token`) }, validateStatus: () => true });
      expect(res.status).toBe(200);
      expect(res.data.token_type).toBe('DPoP');
      expect(res.data.refresh_token).toBeTruthy();
    });
  });
});
