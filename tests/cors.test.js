import http from 'http';
import axios from 'axios';
import express from 'express';
import cors from '../src/cors.js';

const PORT = 3011;
const URL_BASE = `http://localhost:${PORT}`;

describe('CORS middleware', () => {
  let server;

  beforeAll(async () => {
    const app = express();
    app.use(cors);
    app.get('/xrpc/app.bsky.actor.getProfile', (req, res) => res.json({ ok: true }));
    server = http.createServer(app);
    await new Promise((resolve) => server.listen(PORT, resolve));
  });

  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  test('preflight echoes requested headers (e.g. x-atproto-session-id from bsky.app)', async () => {
    const requested = 'authorization,atproto-proxy,atproto-accept-labelers,x-atproto-session-id,x-some-future-header';
    const res = await axios.options(`${URL_BASE}/xrpc/app.bsky.actor.getProfile`, {
      headers: {
        Origin: 'https://bsky.app',
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': requested,
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe('https://bsky.app');
    expect(res.headers['access-control-allow-headers']).toBe(requested);
    expect(res.headers['access-control-allow-methods']).toContain('GET');
  });

  test('non-preflight responses include x-atproto-session-id in default allowed headers', async () => {
    const res = await axios.get(`${URL_BASE}/xrpc/app.bsky.actor.getProfile`, {
      headers: { Origin: 'https://bsky.app' },
    });
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe('https://bsky.app');
    expect(res.headers['access-control-allow-headers'].toLowerCase()).toContain('x-atproto-session-id');
    expect(res.headers['vary']).toContain('Origin');
  });

  test('requests without Origin get a wildcard origin', async () => {
    const res = await axios.get(`${URL_BASE}/xrpc/app.bsky.actor.getProfile`);
    expect(res.headers['access-control-allow-origin']).toBe('*');
  });
});
