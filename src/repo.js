import { Repo, ReadableBlockstore, BlockMap, blocksToCarFile, WriteOpAction } from '@atproto/repo';
import { CID } from 'multiformats';
import { db } from './db.js';
import * as crypto from '@atproto/crypto';
import { createBlobCid, fixCids } from './util.js';
import * as cbor from '@ipld/dag-cbor';
import axios from 'axios';
import { createHash } from 'crypto';
import { sequencer } from './sequencer.js';

export class TursoStorage extends ReadableBlockstore {
  blocks = new BlockMap();
  newBlocks = new BlockMap();
  root = null;

  async getBytes(cid) {
    const cached = this.blocks.get(cid);
    if (cached) return cached;
    const res = await db.execute({
      sql: 'SELECT block FROM repo_blocks WHERE cid = ?',
      args: [cid.toString()]
    });
    if (res.rows.length === 0) return null;
    const bytes = new Uint8Array(res.rows[0].block);
    this.blocks.set(cid, bytes);
    return bytes;
  }

  async has(cid) {
    if (this.blocks.has(cid)) return true;
    const res = await db.execute({
      sql: 'SELECT 1 FROM repo_blocks WHERE cid = ?',
      args: [cid.toString()]
    });
    return res.rows.length > 0;
  }

  async getBlocks(cids) {
    const blocks = new BlockMap();
    const missing = [];
    for (const cid of cids) {
      const bytes = await this.getBytes(cid);
      if (bytes) {
        blocks.set(cid, bytes);
      } else {
        missing.push(cid);
      }
    }
    return { blocks, missing };
  }

  async getRoot() {
    return this.root;
  }

  async putBlock(cid, block) {
    this.blocks.set(cid, block);
    this.newBlocks.set(cid, block);
    await db.execute({
      sql: 'INSERT OR IGNORE INTO repo_blocks (cid, block) VALUES (?, ?)',
      args: [cid.toString(), block]
    });
  }

  async putMany(blocks) {
    for (const [cid, bytes] of blocks) {
      await this.putBlock(cid, bytes);
    }
  }

  async updateRoot(cid) {
    this.root = cid;
  }

  async applyCommit(commit) {
    this.root = commit.cid;
    await this.putMany(commit.newBlocks);
  }

  async getRepoBlocks() {
    const res = await db.execute('SELECT cid, block FROM repo_blocks');
    const blocks = new BlockMap();
    for (const row of res.rows) {
      blocks.set(CID.parse(row.cid), new Uint8Array(row.block));
    }
    return blocks;
  }
}

export async function loadRepo(storage, did, keypair, rootCid) {
  if (!rootCid) {
    const commit = await Repo.formatInitCommit(storage, did, keypair);
    return await Repo.createFromCommit(storage, commit);
  }
  return await Repo.load(storage, CID.parse(rootCid));
}

// --- Repo write serialization ---
// Every write loads the current root, applies its ops and commits a new root.
// Without serialization, two concurrent writes build on the same parent and
// the later one silently drops the earlier one (and breaks the firehose
// commit chain). This is a single-process mutex, which is sufficient as long
// as the PDS runs as a single dyno/instance.
const REPO_LOCK_MAX_HOLD_MS = 30_000; // Heroku's request timeout
let repoLockTail = Promise.resolve();

/** Resolves to an idempotent release() function once the lock is held. */
export function acquireRepoWriteLock() {
  let releaseNext;
  const held = new Promise((resolve) => { releaseNext = resolve; });
  const previous = repoLockTail;
  repoLockTail = previous.then(() => held);

  return previous.then(() => {
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      clearTimeout(timer);
      releaseNext();
    };
    const timer = setTimeout(() => {
      console.warn('[REPO_LOCK] Write lock held too long; force-releasing');
      release();
    }, REPO_LOCK_MAX_HOLD_MS);
    timer.unref?.();
    return release;
  });
}

export const getRootCid = async () => {
  try {
    const res = await db.execute({
      sql: "SELECT event FROM sequencer WHERE type = 'commit' ORDER BY seq DESC LIMIT 1"
    });
    if (res.rows.length === 0) return null;
    const event = cbor.decode(new Uint8Array(res.rows[0].event));
    if (!event.commit) return null;
    if (typeof event.commit === 'string') return event.commit;
    
    // If it's a cborg-style CID object, convert it
    if (event.commit.asCID === event.commit || event.commit._Symbol_for_multiformats_cid) {
        return event.commit.toString();
    }
    
    // Fallback for plain objects from cborg
    try {
        return CID.decode(event.commit.bytes || event.commit).toString();
    } catch (e) {
        // If all else fails, try to see if it has a / link (common in some CID JSON formats)
        return (event.commit['/'] || event.commit).toString();
    }
  } catch (e) {
    console.error('Error in getRootCid:', e);
    return null; 
  }
};

export async function setUpRepo() {
  const rootCid = await getRootCid();
  if (rootCid) return;

  const privKeyHex = process.env.PRIVATE_KEY;
  const did = process.env.PDS_DID?.trim();

  if (!did) throw new Error('PDS_DID environment variable is not set');
  if (!privKeyHex) {
    console.log('PRIVATE_KEY not found. Skipping repo auto-init.');
    return;
  }

  const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(Buffer.from(privKeyHex, 'hex')));

  console.log(`Auto-initializing empty PDS repo for ${did}...`);
  const storage = new TursoStorage();
  
  // Create an initial empty repo
  const repo = await loadRepo(storage, did, keypair, null);
  const carBlocks = await storage.getRepoBlocks();
  const blocks = await blocksToCarFile(repo.cid, carBlocks);

  await sequencer.sequenceEvent({
    type: 'commit',
    did: did,
    event: {
      repo: did,
      commit: repo.cid,
      blocks,
      rev: repo.commit.rev,
      since: null,
      ops: [], // Empty genesis
      blobs: [],
      time: new Date().toISOString(),
      rebase: false,
      tooBig: false,
    }
  });

  console.log(`Empty Repo initialized successfully. Root CID: ${repo.cid.toString()}`);
}
