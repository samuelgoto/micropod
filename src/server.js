import express from 'express';
import path from 'path';
import { db } from './db.js';
import { createToken, verifyToken, validateDpop, getJkt, createServiceAuthToken, auth, oauth } from './auth.js';
import { TursoStorage, getRootCid, setUpRepo } from './repo.js';
import { Repo, WriteOpAction, blocksToCarFile } from '@atproto/repo';
import * as crypto from '@atproto/crypto';
import { createHash, randomBytes, createPublicKey, createECDH } from 'crypto';
import { CID } from 'multiformats';
import { sequencer } from './sequencer.js';
import { WebSocketServer } from 'ws';
import axios from 'axios';
import { createBlobCid, fixCids, getDidDoc, verifyPassword } from './util.js';
import { rateLimit } from 'express-rate-limit';
import { TID } from '@atproto/common';
import * as cbor from '@ipld/dag-cbor';
import oauthRouter from './oauth.js';
import admin from './admin.js';
import proxy from './proxy.js';
import cors from './cors.js';
import helmet from 'helmet';
import fedcmRouter from './fedcm.js';
import loginRouter from './login.js';
import { attachSession } from './session.js';
import { fileURLToPath } from 'url';

const app = express();
app.set('trust proxy', true);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FAVICON_PATH = path.join(__dirname, '..', 'assets', 'favicon.ico');

const isLocalDevRequest = (req) => {
  const host = req.get('host') || '';
  return host.includes('localhost') || host.includes('127.0.0.1');
};

// 1. Global API Limiter (Protects the whole server from DoS)
const globalLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	limit: 5000, // Increased to 5000 requests per 15 mins (approx 333/min)
	standardHeaders: true,
	legacyHeaders: false,
  validate: { trustProxy: false },
  skip: isLocalDevRequest,
  message: { error: 'RateLimitExceeded', message: 'Too many requests. Please try again later.' }
});

// 2. Strict Auth Limiter (Brute-force protection)
const authLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	limit: 1000, // Increased to 1000 for single-user convenience
	standardHeaders: true,
	legacyHeaders: false,
  validate: { trustProxy: false },
  skip: isLocalDevRequest,
  message: { error: 'RateLimitExceeded', message: 'Too many login attempts. Please try again later.' }
});

// 3. Write Limiter (Prevents rapid-fire repo updates)
const writeLimiter = rateLimit({
	windowMs: 1 * 60 * 1000, // 1 minute
	limit: 300, // Increased to 300 writes per minute
	standardHeaders: true,
	legacyHeaders: false,
  validate: { trustProxy: false },
  skip: isLocalDevRequest,
  message: { error: 'RateLimitExceeded', message: 'Too many write operations. Please slow down.' }
});

// CORS must run before rate limiting so that preflights are answered without
// counting against the limit, and so 429 responses still carry CORS headers
// (otherwise the browser reports them as opaque CORS failures).
app.use(cors);

app.use(globalLimiter);

export const wss = new WebSocketServer({ noServer: true });

// Unify WebSocket handling via Sequencer
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const cursor = url.searchParams.get('cursor');
  sequencer.addClient(ws, cursor ? parseInt(cursor, 10) : undefined);
});

// Remove broadcastRepoUpdate as it's handled by sequencer.sequenceEvent

// 1. CORS middleware is registered above, before the global rate limiter.

// 2. Security Headers (Helmet)
app.use(helmet({
  contentSecurityPolicy: false, // Disabled for dashboard inline scripts/images
  crossOriginResourcePolicy: { policy: "cross-origin" } // Allow images from AppViews
}));

// 3. JSON parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- PDS User Context Middleware ---
app.use(async (req, res, next) => {
  const handle = process.env.HANDLE;
  const did = process.env.PDS_DID?.trim();
  const privKeyHex = process.env.PRIVATE_KEY;
  const password = process.env.PASSWORD;
  
  if (!handle || !did || !password) {
    throw new Error('Crucial environment variables missing at runtime');
  }
  
  const root_cid = await getRootCid();
  if (!root_cid) {
    throw new Error('Repository not initialized. Check server startup logs.');
  }

  const host = req.get('host') || process.env.DOMAIN || 'localhost';
  const isProd = process.env.NODE_ENV === 'production' || (!host.includes('localhost') && !host.includes('127.0.0.1'));
  const protocol = (req.protocol === 'https' || isProd) ? 'https' : 'http';
  
  req.user = {
    handle,
    password,
    did,
    signing_key: Buffer.from(privKeyHex, 'hex'),
    root_cid: root_cid.toString(),
    email: process.env.EMAIL || `pds@${handle}`,
    birthDate: process.env.BIRTHDATE || '1990-01-01',
    protocol,
    host,
    issuer: `${protocol}://${host}`
  };
  next();
});

app.use(attachSession);
app.use(oauthRouter);
app.use(loginRouter);
app.use(fedcmRouter);
app.use(admin);

app.get('/xrpc/com.atproto.server.describeServer', async (req, res) => {
  const pdsDid = req.user.did;
  res.json({ availableUserDomains: [], did: pdsDid });
});

app.get('/xrpc/com.atproto.server.getServiceContext', async (req, res) => {
  res.json({
    did: req.user.did,
    endpoint: req.user.issuer
  });
});

app.post('/xrpc/com.atproto.identity.updateHandle', auth, oauth('atproto'), async (req, res) => {
  const { handle } = req.body;
  if (handle !== req.user.handle) {
    return res.status(400).json({ 
      error: 'InvalidRequest', 
      message: `This PDS only supports the handle ${req.user.handle}. Please update your .env if you wish to change it.` 
    });
  }
  
  console.log(`[FIREHOSE] Emitting #identity and #account for ${req.user.did} due to handle update`);
  
  await sequencer.sequenceEvent({
    type: 'identity',
    did: req.user.did,
    event: {
      did: req.user.did,
      time: new Date().toISOString(),
    }
  });

  await sequencer.sequenceEvent({
    type: 'account',
    did: req.user.did,
    event: {
      did: req.user.did,
      active: true,
      time: new Date().toISOString(),
    }
  });

  res.json({});
});

// 4. Favicon handler
app.get('/favicon.ico', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=604800, immutable');
  res.sendFile(FAVICON_PATH);
});

// Helper to get system state

// Helper to get the current host safely

const getBlobUrl = (req, blob) => {
  if (!blob || !blob.ref || !blob.ref.$link) return undefined;
  const user = req.user;
  return `${user.protocol}://${user.host}/xrpc/com.atproto.sync.getBlob?cid=${blob.ref.$link}`;
};

// Helper to get the single allowed user from Env

// --- Endpoints ---
app.get('/.well-known/atproto-did', async (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Cache-Control', 'no-cache');
  // Use res.write and res.end to ensure absolutely no extra formatting
  res.write(req.user.did);
  res.end();
});

app.get('/xrpc/com.atproto.identity.getRecommendedDidCredentials', async (req, res) => {
  res.json({
    rotationKeys: [],
    alsoKnownAs: [`at://${req.user.handle}`],
    verificationMethods: {},
    services: {}
  });
});


app.get('/xrpc/com.atproto.identity.resolveDid', async (req, res) => {
  const { did } = req.query;
  if (!did) return res.status(400).json({ error: 'InvalidRequest', message: 'Missing did' });

  if (did.toLowerCase() === req.user.did.toLowerCase()) {
    const doc = await getDidDoc(req.user, req.user.host);
    if (!doc) return res.status(404).json({ error: 'DidNotFound' });
    return res.json(doc);
  }

  // Proxy other DIDs to plc.directory if they are did:plc
  if (did.startsWith('did:plc:')) {
    console.log(`Proxying resolveDid for ${did} to plc.directory...`);
    const plcRes = await axios.get(`https://plc.directory/${did}`, { timeout: 5000 });
    return res.json(plcRes.data);
  }

  res.status(404).json({ error: 'DidNotFound' });
});

app.get('/xrpc/com.atproto.identity.resolveHandle', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const { handle } = req.query;

  // Only resolve locally if the handle EXACTLY matches our domain or is empty/self
  if (!handle || handle === req.user.handle || handle === 'self') {
    console.log(`[RESOLVE] Local handle resolved: ${handle || 'default'} -> ${req.user.did}`);
    return res.json({ did: req.user.did.trim() });
  }

  // 2. Otherwise, proxy the request to a public AppView to resolve other handles
  console.log(`[RESOLVE] Proxying handle resolution to bsky.social for: ${handle}`);
  const appView = 'https://bsky.social';
  const response = await axios.get(`${appView}/xrpc/com.atproto.identity.resolveHandle?handle=${handle}`, {
      timeout: 5000,
      validateStatus: (status) => status === 200 || status === 404
  });

  if (response.status === 200) {
      console.log(`[RESOLVE] External handle resolved via bsky.social: ${handle} -> ${response.data.did}`);
      return res.json(response.data);
  }

  return res.status(404).json({ error: 'HandleNotFound' });
});
app.post('/xrpc/com.atproto.server.createSession', authLimiter, async (req, res) => {
  const { identifier, password } = req.body;
  const user = req.user;
  if (!user) {
    console.log('Login failed: Server not initialized (no user)');
    return res.status(500).json({ error: 'ServerNotInitialized' });
  }

  if (identifier !== user.handle && identifier !== user.did) {
    console.log(`Login failed: Invalid identifier. Received: ${identifier}, Expected: ${user.handle} or ${user.did}`);
    return res.status(401).json({ error: 'InvalidIdentifier' });
  }

  if (!verifyPassword(password, user.password)) {
    console.log(`Login failed: Password mismatch for ${identifier}`);
    return res.status(401).json({ error: 'InvalidPassword' });
  }

  const accessJwt = await createToken(user.did, user.handle);  res.json({ accessJwt, refreshJwt: accessJwt, handle: user.handle, did: user.did });
});

app.post('/xrpc/com.atproto.server.refreshSession', authLimiter, auth, async (req, res) => {
  const user = req.user;
  if (!user) return res.status(500).json({ error: 'ServerNotInitialized' });
  
  const accessJwt = await createToken(user.auth.sub, user.auth.handle);
  res.json({ accessJwt, refreshJwt: accessJwt, handle: user.auth.handle, did: user.auth.sub });
});

app.get('/xrpc/com.atproto.server.getAccount', auth, oauth('atproto'), async (req, res) => {
  const user = req.user;
  
  const birthDateRes = await db.execute({
    sql: 'SELECT value FROM preferences WHERE key = ?',
    args: [`birthDate:${user.did}`]
  });
  const birthDate = birthDateRes.rows[0]?.value || user.birthDate;

  res.json({
    handle: user.handle,
    did: user.did,
    email: user.email,
    emailConfirmed: true,
    birthDate: birthDate,
  });
});

app.get('/xrpc/com.atproto.server.checkAccountStatus', async (req, res) => {
  res.json({
    activated: true,
    validEmail: true,
    repoCommit: await getRootCid(),
    repoRev: '0',
    repoBlocks: 1,
    indexedIncremental: true,
    expectedBlobs: 0,
    importedBlobs: 0
  });
});

app.get('/xrpc/com.atproto.server.getSession', auth, oauth('atproto'), async (req, res) => {
  const didDoc = await getDidDoc(req.user, req.user.host);
  res.json({ 
    handle: req.user.auth.handle, 
    did: req.user.auth.sub,
    email: req.user.email,
    emailConfirmed: true,
    active: true,
    status: 'active',
    didDoc
  });
});

app.get('/xrpc/app.bsky.actor.getPreferences', auth, oauth('atproto'), async (req, res) => {
  const prefsRes = await db.execute({
    sql: 'SELECT value FROM preferences WHERE key = ?',
    args: [`prefs:${req.user.auth.sub}`]
  });
  const prefsJson = prefsRes.rows[0]?.value;
  let preferences = prefsJson ? JSON.parse(prefsJson) : [];
  
  // ATProto nuance: PDS is the source of truth for user preferences
  if (!preferences.find(p => p.$type === 'app.bsky.actor.defs#adultContentPref')) {
      preferences.push({
          $type: 'app.bsky.actor.defs#adultContentPref',
          enabled: true
      });
  }

  res.json({ preferences });
});

app.post('/xrpc/app.bsky.actor.putPreferences', auth, oauth('atproto'), async (req, res) => {
  const { preferences } = req.body;
  
  // Extract and store birthDate if provided in personalDetailsPref
  const personalDetailsPref = preferences.find(p => p.$type === 'app.bsky.actor.defs#personalDetailsPref');
  if (personalDetailsPref?.birthDate) {
      await db.execute({
          sql: "INSERT OR REPLACE INTO preferences (key, value) VALUES (?, ?)",
          args: [`birthDate:${req.user.auth.sub}`, personalDetailsPref.birthDate]
      });
  }

  await db.execute({
    sql: "INSERT OR REPLACE INTO preferences (key, value) VALUES (?, ?)",
    args: [`prefs:${req.user.auth.sub}`, JSON.stringify(preferences)]
  });
  res.json({});
});

app.post('/xrpc/com.atproto.repo.createRecord', writeLimiter, auth, oauth('atproto'), async (req, res) => {
    const { repo, collection, record, rkey } = req.body;
    if (repo !== req.user.did) return res.status(403).json({ error: 'InvalidRepo' });
    
    // ATProto nuance: records from clients often have CID strings. 
    // They MUST be CID objects for proper Tag 42 storage.
    const fixedRecord = fixCids(record);

    const storage = new TursoStorage();
    const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(req.user.signing_key));
    const repoObj = await Repo.load(storage, CID.parse(req.user.root_cid));
    
    const finalRkey = rkey || TID.nextStr();
    const updatedRepo = await repoObj.applyWrites([{ action: WriteOpAction.Create, collection, rkey: finalRkey, record: fixedRecord }], keypair);
    
    const recordCid = await updatedRepo.data.get(collection + '/' + finalRkey);
    const blocks = await blocksToCarFile(updatedRepo.cid, storage.newBlocks);
    const opCid = typeof recordCid === 'string' ? CID.parse(recordCid) : recordCid;

    await sequencer.sequenceEvent({
      type: 'commit',
      did: req.user.did,
      event: {
        repo: req.user.did,
        commit: updatedRepo.cid,
        blocks: blocks,
        rev: updatedRepo.commit.rev,
        since: repoObj.commit.rev,
        ops: [{ action: 'create', path: `${collection}/${finalRkey}`, cid: opCid }],
        blobs: [], // Placeholder
        time: new Date().toISOString(),
        rebase: false,
        tooBig: false,
      }
    });
    
    res.json({ 
        uri: `at://${req.user.did}/${collection}/${finalRkey}`, 
        cid: recordCid?.toString() || updatedRepo.cid.toString(),
        commit: {
            cid: updatedRepo.cid.toString(),
            rev: updatedRepo.commit.rev
        }
    });
});

app.post('/xrpc/com.atproto.repo.putRecord', writeLimiter, auth, oauth('atproto'), async (req, res) => {
  const { repo, collection, rkey, record } = req.body;
  if (repo !== req.user.did) return res.status(403).json({ error: 'InvalidRepo' });

  const fixedRecord = fixCids(record);

  const storage = new TursoStorage();
  const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(req.user.signing_key));
  const repoObj = await Repo.load(storage, CID.parse(req.user.root_cid));

  const updatedRepo = await repoObj.applyWrites([{ action: WriteOpAction.Update, collection, rkey, record: fixedRecord }], keypair);
  const recordCid = await updatedRepo.data.get(collection + '/' + rkey);
  const blocks = await blocksToCarFile(updatedRepo.cid, storage.newBlocks);
  const opCid = typeof recordCid === 'string' ? CID.parse(recordCid) : recordCid;

  await sequencer.sequenceEvent({
    type: 'commit',
    did: req.user.did,
    event: {
      repo: req.user.did,
      commit: updatedRepo.cid,
      blocks: blocks,
      rev: updatedRepo.commit.rev,
      since: repoObj.commit.rev,
      ops: [{ action: 'update', path: `${collection}/${rkey}`, cid: opCid }],
      blobs: [],
      time: new Date().toISOString(),
      rebase: false,
      tooBig: false,
    }
  });
  
  res.json({ 
      uri: `at://${req.user.did}/${collection}/${rkey}`, 
      cid: recordCid?.toString() || updatedRepo.cid.toString(),
      commit: {
          cid: updatedRepo.cid.toString(),
          rev: updatedRepo.commit.rev
      }
  });
});

app.post('/xrpc/com.atproto.repo.deleteRecord', writeLimiter, auth, oauth('atproto'), async (req, res) => {
  const { repo, collection, rkey } = req.body;
  if (repo !== req.user.did) return res.status(403).json({ error: 'InvalidRepo' });
  
  const storage = new TursoStorage();
  const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(req.user.signing_key));
  const repoObj = await Repo.load(storage, CID.parse(req.user.root_cid));
  
  const updatedRepo = await repoObj.applyWrites([{ action: WriteOpAction.Delete, collection, rkey }], keypair);
  const blocks = await blocksToCarFile(updatedRepo.cid, storage.newBlocks);

  await sequencer.sequenceEvent({
    type: 'commit',
    did: req.user.did,
    event: {
      repo: req.user.did,
      commit: updatedRepo.cid,
      blocks: blocks,
      rev: updatedRepo.commit.rev,
      since: repoObj.commit.rev,
      ops: [{ action: 'delete', path: `${collection}/${rkey}`, cid: null }],
      blobs: [],
      time: new Date().toISOString(),
      rebase: false,
      tooBig: false,
    }
  });
  
  res.json({ commit: { cid: updatedRepo.cid.toString(), rev: updatedRepo.commit.rev } });
});

app.post('/xrpc/com.atproto.repo.applyWrites', writeLimiter, auth, oauth('atproto'), async (req, res) => {
  const { repo, writes } = req.body;
  if (repo !== req.user.did) return res.status(403).json({ error: 'InvalidRepo' });

  const storage = new TursoStorage();
  const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(req.user.signing_key));
  const repoObj = await Repo.load(storage, CID.parse(req.user.root_cid));

  const repoWrites = writes.map(w => {
      if (w.$type === 'com.atproto.repo.applyWrites#create') {
          return { action: WriteOpAction.Create, collection: w.collection, rkey: w.rkey || TID.nextStr(), record: fixCids(w.value) };
      } else if (w.$type === 'com.atproto.repo.applyWrites#update') {
          return { action: WriteOpAction.Update, collection: w.collection, rkey: w.rkey, record: fixCids(w.value) };
      } else if (w.$type === 'com.atproto.repo.applyWrites#delete') {
          return { action: WriteOpAction.Delete, collection: w.collection, rkey: w.rkey };
      }
      throw new Error(`Unknown write action: ${w.$type}`);
  });

  const updatedRepo = await repoObj.applyWrites(repoWrites, keypair);

  // Prepare ops for the sequencer event
  const ops = [];
  for (const w of repoWrites) {
      let cid = null;
      if (w.action !== WriteOpAction.Delete) {
          const rawCid = await updatedRepo.data.get(w.collection + '/' + w.rkey);
          cid = typeof rawCid === 'string' ? CID.parse(rawCid) : rawCid;
      }
      ops.push({
          action: w.action.toLowerCase(),
          path: `${w.collection}/${w.rkey}`,
          cid: cid
      });
  }
  const blocks = await blocksToCarFile(updatedRepo.cid, storage.newBlocks);

  await sequencer.sequenceEvent({
    did: req.user.did,
    type: 'commit',
    event: {
      repo: req.user.did,
      commit: updatedRepo.cid,
      blocks: blocks,
      rev: updatedRepo.commit.rev,
      since: repoObj.commit.rev,
      ops: ops,
      time: new Date().toISOString(),
      rebase: false,
      tooBig: false,
      blobs: [],
    }
  });

  res.json({ commit: { cid: updatedRepo.cid.toString(), rev: updatedRepo.commit.rev } });
});

app.post('/xrpc/com.atproto.repo.uploadBlob', writeLimiter, auth, oauth('atproto'), express.raw({ type: '*/*', limit: '5mb' }), async (req, res) => {
  const content = req.body;
  const mimeType = req.headers['content-type'] || 'application/octet-stream';
  
  // Generate valid CIDv1
  const cid = await createBlobCid(content);

  await db.execute({
    sql: "INSERT OR REPLACE INTO blobs (cid, did, mime_type, content, created_at) VALUES (?, ?, ?, ?, ?)",
    args: [cid, req.user.did, mimeType, content, new Date().toISOString()]
  });

  res.json({
    blob: {
      $type: 'blob',
      ref: { $link: cid },
      mimeType: mimeType,
      size: content.length,
    }
  });
});

app.get('/xrpc/com.atproto.sync.getBlob', async (req, res) => {
  const { cid } = req.query;
  
  const result = await db.execute({
    sql: "SELECT mime_type, content FROM blobs WHERE cid = ?",
    args: [cid]
  });

  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'BlobNotFound' });
  }

  const { mime_type, content } = result.rows[0];
  res.setHeader('Content-Type', mime_type);
  res.send(Buffer.from(content));
});

// Helper to get a single record from the local repo
const getRecordHelper = async (repo, collection, rkey, user) => {
  if (!user) {
    console.log('[HELPER] No user found');
    return null;
  }
  
  const isMatch = repo.toLowerCase() === user.did.toLowerCase() || repo.toLowerCase() === user.handle.toLowerCase();
  if (!isMatch) {
    console.log(`[HELPER] Repo mismatch: ${repo} !== ${user.did} or ${user.handle}`);
    return null;
  }

  try {
    const storage = new TursoStorage();
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    const value = await repoObj.getRecord(collection, rkey);
    
    if (!value) {
        console.log(`[HELPER] Record not found: ${collection}/${rkey}`);
        return null;
    }
    
    const cid = await repoObj.data.get(`${collection}/${rkey}`);
    return { value, cid: cid.toString() };
  } catch (err) {
    console.error(`[HELPER] Error fetching ${collection}/${rkey}:`, err.message);
    return null;
  }
};

app.get('/xrpc/com.atproto.repo.listRecords', async (req, res, next) => {
    const { repo, collection } = req.query;
    if (repo.toLowerCase() !== req.user.did.toLowerCase() && repo.toLowerCase() !== req.user.handle.toLowerCase()) {
        return next();
    }

    const storage = new TursoStorage();
    const repoObj = await Repo.load(storage, CID.parse(req.user.root_cid));
    const entries = await repoObj.data.list(collection + '/');
    
    const records = [];
    for (const entry of entries) {
        const rkey = entry.key.split('/').pop();
        const value = await repoObj.getRecord(collection, rkey);
        if (value) {
            records.push({
                uri: `at://${req.user.did}/${collection}/${rkey}`,
                cid: entry.value.toString(),
                value
            });
        }
    }

    res.json({ records });
});

app.get('/xrpc/com.atproto.repo.getRecord', async (req, res, next) => {
  const { repo, collection, rkey } = req.query;
  const isLocalRepo = typeof repo === 'string' &&
    (repo.toLowerCase() === req.user.did.toLowerCase() || repo.toLowerCase() === req.user.handle.toLowerCase());
  // Not our repo: let it fall through (e.g. to the proxy).
  if (!isLocalRepo) return next();

  const record = await getRecordHelper(repo, collection, rkey, req.user);
  if (!record) {
    // Match the reference PDS: a missing record in our own repo is a 400 RecordNotFound,
    // not a 404 MethodNotFound (clients check for this error name).
    return res.status(400).json({
      error: 'RecordNotFound',
      message: `Could not locate record: at://${req.user.did}/${collection}/${rkey}`
    });
  }
  
  res.json({ uri: `at://${repo}/${collection}/${rkey}`, value: record.value, cid: record.cid });
});

app.get('/xrpc/com.atproto.repo.describeRepo', async (req, res, next) => {
    const { repo } = req.query;
    if (repo !== req.user.did && repo !== req.user.handle) {
        return next();
    }

    const didDoc = await getDidDoc(req.user, req.user.host);

    res.json({
        handle: req.user.handle,
        did: req.user.did,
        didDoc: didDoc,
        collections: [
            'app.bsky.actor.profile',
            'app.bsky.feed.post',
            'app.bsky.feed.like',
            'app.bsky.feed.repost',
            'app.bsky.graph.follow'
        ],
        handleIsCorrect: true,
    });
});

app.get('/xrpc/com.atproto.sync.getRecord', async (req, res) => {
  const { did, collection, rkey } = req.query;
  const pdsDid = req.user.did;
  if (did && did !== pdsDid) return res.status(404).json({ error: 'RepoNotFound' });

  const storage = new TursoStorage();
  const rootCid = await getRootCid();
  const repoObj = await Repo.load(storage, CID.parse(rootCid));
  const record = await repoObj.getRecord(collection, rkey);

  if (!record) return res.status(404).json({ error: 'RecordNotFound' });

  // Note: getRecord in sync usually returns proof (blocks), but we'll provide the data
  res.json({
      uri: `at://${did}/${collection}/${rkey}`,
      cid: (await repoObj.data.get(`${collection}/${rkey}`)).toString(),
      value: record
  });
});

app.head('/xrpc/com.atproto.sync.getHead', (req, res) => res.status(200).end());
app.get('/xrpc/com.atproto.sync.getHead', async (req, res) => {
  const { did } = req.query;
  const pdsDid = req.user.did;
  if (did && did.toLowerCase() !== pdsDid.toLowerCase()) {
      return res.status(404).json({ error: 'RepoNotFound' });
  }

  const rootCid = await getRootCid();
  if (!rootCid) {
      return res.status(404).json({ error: 'RepoNotFound' });
  }

  res.json({ root: rootCid });
});

app.head('/xrpc/com.atproto.sync.getLatestCommit', (req, res) => res.status(200).end());
app.get('/xrpc/com.atproto.sync.getLatestCommit', async (req, res) => {
  const { did } = req.query;
  const pdsDid = req.user.did;
  if (did && did !== pdsDid) {
      return res.status(404).json({ error: 'RepoNotFound' });
  }

  const rootCid = await getRootCid();
  const result = await db.execute({
    sql: 'SELECT event FROM sequencer WHERE type = "commit" ORDER BY seq DESC LIMIT 1',
  });

  if (result.rows.length === 0 || !rootCid) {
      return res.status(404).json({ error: 'RepoNotFound' });
  }
  const event = cbor.decode(new Uint8Array(result.rows[0].event));

  res.json({
      cid: rootCid,
      rev: event.rev,
  });
});

app.post('/xrpc/com.atproto.server.activateAccount', auth, oauth('atproto'), async (req, res) => {
  console.log(`[FIREHOSE] Emitting #identity and #account for ${req.user.did}`);
  
  await sequencer.sequenceEvent({
    type: 'identity',
    did: req.user.did,
    event: {
      did: req.user.did,
      time: new Date().toISOString(),
    }
  });

  await sequencer.sequenceEvent({
    type: 'account',
    did: req.user.did,
    event: {
      did: req.user.did,
      active: true,
      time: new Date().toISOString(),
    }
  });

  res.json({});
});

app.get('/xrpc/_health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0' });
});

app.get('/xrpc/com.atproto.sync.getRepoStatus', async (req, res) => {
  const { did } = req.query;
  const pdsDid = req.user.did;
  if (did && did.toLowerCase() !== pdsDid.toLowerCase()) {
    return res.status(404).json({ error: 'RepoNotFound' });
  }

  const result = await db.execute({
    sql: 'SELECT event FROM sequencer WHERE type = "commit" ORDER BY seq DESC LIMIT 1',
  });

  let rev = '';
  if (result.rows.length > 0) {
    const event = cbor.decode(new Uint8Array(result.rows[0].event));
    rev = event.rev || '';
  }

  res.json({
    did: pdsDid,
    active: true,
    status: 'active',
    rev: rev
  });
});

app.get('/xrpc/com.atproto.sync.listRepos', async (req, res) => {
  const pdsDid = req.user.did;
  const rootCid = await getRootCid();
  if (!rootCid) {
      return res.json({ repos: [] });
  }

  res.json({
    repos: [
      {
        did: pdsDid,
        head: rootCid.toString(),
        rev: '0'
      }
    ]
  });
});
// WebSocket Firehose for subscribeRepos
app.get('/xrpc/com.atproto.sync.subscribeRepos', async (req, res) => {
  // If this is a regular HTTP request, provide a helpful message
  if (req.headers.upgrade !== 'websocket') {
    return res.status(200).send('WebSocket firehose endpoint. Use a WebSocket client to subscribe.');
  }
  // WebSocket upgrades are handled at the server level (see api/index.js)
});

app.get('/xrpc/com.atproto.sync.getBlocks', async (req, res) => {
  const { did, cids } = req.query;
  const user = req.user;
  const pdsDid = user?.did;
  if (did && pdsDid && did !== pdsDid) return res.status(404).json({ error: 'RepoNotFound' });

  const storage = new TursoStorage();
  const requestedCids = Array.isArray(cids) ? cids : [cids];
  const parsedCids = requestedCids.filter(Boolean).map((cidStr) => CID.parse(cidStr));
  if (parsedCids.length === 0) {
    return res.status(400).json({ error: 'InvalidRequest', message: 'Missing cids' });
  }

  const { blocks } = await storage.getBlocks(parsedCids);
  const car = await blocksToCarFile(parsedCids[0], blocks);
  res.setHeader('Content-Type', 'application/vnd.ipld.car');
  res.send(Buffer.from(car));
});

app.get('/xrpc/com.atproto.sync.getRepo', async (req, res) => {
  const { did } = req.query;
  const pdsDid = req.user.did;
  if (did && did !== pdsDid) return res.status(404).json({ error: 'RepoNotFound' });
  
  const rootCid = await getRootCid();
  if (!rootCid) return res.status(404).json({ error: 'RepoNotFound' });

  const storage = new TursoStorage();
  const blocks = await storage.getRepoBlocks();
  const car = await blocksToCarFile(CID.parse(rootCid), blocks);

  res.setHeader('Content-Type', 'application/vnd.ipld.car');
  res.send(Buffer.from(car));
});

app.get('/xrpc/com.atproto.sync.getCheckout', async (req, res) => {
  const { did } = req.query;
  const pdsDid = req.user.did;
  if (did && did !== pdsDid) return res.status(404).json({ error: 'RepoNotFound' });
  
  const rootCid = await getRootCid();
  if (!rootCid) return res.status(404).json({ error: 'RepoNotFound' });

  const storage = new TursoStorage();
  const blocks = await storage.getRepoBlocks();
  const car = await blocksToCarFile(CID.parse(rootCid), blocks);

  res.setHeader('Content-Type', 'application/vnd.ipld.car');
  res.send(Buffer.from(car));
});

app.use(proxy);

// --- 404 Catch-all ---
app.use((req, res, next) => {
  res.status(404).json({
    error: 'MethodNotFound',
    message: `The method ${req.path} does not exist.`
  });
});

// --- Global Error Handler ---
app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  console.error('[GLOBAL_ERROR]', err.stack || err);
  
  const statusCode = err.status || err.statusCode || 500;
  res.status(statusCode).json({
    error: (err.name && err.name !== 'Error') ? err.name : 'InternalServerError',
    message: err.message || 'An unexpected error occurred'
  });
});

export default app;
