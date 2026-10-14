import 'dotenv/config';
import { jest } from '@jest/globals';
import http from 'http';
import axios from 'axios';
import app from '../src/server.js';
import { db, setUpForTesting, create } from '../src/db.js';
import { setUpRepo, getRootCid } from '../src/repo.js';
import { sequencer } from '../src/sequencer.js';
import * as cbor from '@ipld/dag-cbor';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = 3015;
const HOST = `http://localhost:${PORT}`;
const PASSWORD = 'concurrency-pass';

describe('Concurrent repo writes', () => {
  let server;
  let dbPath;
  let token;
  let did;

  beforeAll(async () => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    process.env.PASSWORD = PASSWORD;
    process.env.HANDLE = 'localhost.test';
    dbPath = path.join(__dirname, `concurrency-${Date.now()}.db`);
    await setUpForTesting(`file:${dbPath}`); await create(); await setUpRepo();
    // The local SQLite client completes queries without yielding to the event
    // loop, which hides races. Production uses Turso over the network, where
    // every query yields; simulate that with a small random delay.
    const originalExecute = db.execute.bind(db);
    db.execute = async (...args) => {
      await new Promise((resolve) => setTimeout(resolve, Math.random() * 3));
      return originalExecute(...args);
    };
    did = process.env.PDS_DID.trim();
    server = http.createServer(app);
    await new Promise((resolve) => server.listen(PORT, resolve));
    const res = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
      identifier: 'localhost.test', password: PASSWORD,
    });
    token = res.data.accessJwt;
  });

  afterAll(async () => {
    sequencer.close();
    db.close();
    await new Promise((resolve) => server.close(resolve));
    for (const p of [dbPath, `${dbPath}-shm`, `${dbPath}-wal`]) {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
  });

  const headers = () => ({ Authorization: `Bearer ${token}` });

  test('simultaneous writes are all kept and form a single linear commit chain', async () => {
    const N = 12;
    const writes = Array.from({ length: N }, (_, i) => {
      if (i % 3 === 0) {
        return axios.post(`${HOST}/xrpc/com.atproto.repo.applyWrites`, {
          repo: did,
          writes: [{
            $type: 'com.atproto.repo.applyWrites#create',
            collection: 'app.bsky.feed.like',
            value: { $type: 'app.bsky.feed.like', subject: { uri: `at://${did}/app.bsky.feed.post/x${i}`, cid: 'bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm' }, createdAt: new Date().toISOString() },
          }],
        }, { headers: headers() });
      }
      return axios.post(`${HOST}/xrpc/com.atproto.repo.createRecord`, {
        repo: did,
        collection: 'app.bsky.feed.post',
        record: { $type: 'app.bsky.feed.post', text: `concurrent ${i}`, createdAt: new Date().toISOString() },
      }, { headers: headers() });
    });
    const results = await Promise.all(writes);
    results.forEach((r) => expect(r.status).toBe(200));

    // Every write must be present in the final repo.
    const posts = await axios.get(`${HOST}/xrpc/com.atproto.repo.listRecords`, { params: { repo: did, collection: 'app.bsky.feed.post' } });
    const likes = await axios.get(`${HOST}/xrpc/com.atproto.repo.listRecords`, { params: { repo: did, collection: 'app.bsky.feed.like' } });
    expect(posts.data.records.length + likes.data.records.length).toBe(N);

    // The firehose commit chain must be linear: each commit's `since` is the previous commit's `rev`.
    const rows = await db.execute("SELECT event FROM sequencer WHERE type = 'commit' ORDER BY seq ASC");
    const commits = rows.rows.map((r) => cbor.decode(new Uint8Array(r.event)));
    for (let i = 1; i < commits.length; i++) {
      expect(commits[i].since).toBe(commits[i - 1].rev);
    }
    expect(commits[commits.length - 1].commit.toString()).toBe(await getRootCid());
  });
});
