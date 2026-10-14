import { createClient } from '@libsql/client';

export let db = createClient({
  url: process.env.TURSO_DATABASE_URL || 'file:local.db',
  authToken: process.env.TURSO_AUTH_TOKEN
});

export async function setUpForTesting(url) {
  // We don't necessarily need to close the old one here because 
  // Jest runs suites in isolation, but it's good practice.
  db = createClient({ url, authToken: process.env.TURSO_AUTH_TOKEN });
}

export async function create() {
  await db.batch([
    `CREATE TABLE IF NOT EXISTS repo_blocks (
      cid TEXT PRIMARY KEY,
      block BLOB NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS blobs (
      cid TEXT PRIMARY KEY,
      did TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      content BLOB NOT NULL,
      created_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      handle TEXT NOT NULL,
      did TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS sequencer (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      did TEXT NOT NULL,
      type TEXT NOT NULL,
      event BLOB NOT NULL,
      time TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS preferences (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS oauth_codes (
      code TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      scope TEXT NOT NULL,
      did TEXT NOT NULL,
      dpop_jwk TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      format TEXT,
      me TEXT,
      metadata_endpoint TEXT,
      profile TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
      token TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      did TEXT NOT NULL,
      scope TEXT NOT NULL,
      dpop_jwk TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS oauth_par_requests (
      request_uri TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      request_data TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    )`,
    // Legacy app sessions (createSession/refreshSession/deleteSession). See app-sessions.js.
    `CREATE TABLE IF NOT EXISTS app_sessions (
      sid TEXT PRIMARY KEY,
      did TEXT NOT NULL,
      handle TEXT NOT NULL,
      refresh_jti TEXT NOT NULL,
      prev_refresh_jti TEXT,
      prev_valid_until INTEGER,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )`
  ], "write");

  const oauthCodeColumnMigrations = [
    'ALTER TABLE oauth_codes ADD COLUMN format TEXT',
    'ALTER TABLE oauth_codes ADD COLUMN me TEXT',
    'ALTER TABLE oauth_codes ADD COLUMN metadata_endpoint TEXT',
    'ALTER TABLE oauth_codes ADD COLUMN profile TEXT',
  ];

  for (const sql of oauthCodeColumnMigrations) {
    try {
      await db.execute(sql);
    } catch (err) {
      if (!String(err?.message || '').includes('duplicate column name')) {
        throw err;
      }
    }
  }
}

export async function disconnect() {
  if (db) {
    await db.close();
  }
}

export async function destroy() {
  await db.batch([
    'DELETE FROM repo_blocks',
    'DELETE FROM sequencer',
    'DELETE FROM blobs',
    'DELETE FROM sessions',
    'DELETE FROM preferences',
    'DELETE FROM oauth_codes',
    'DELETE FROM oauth_refresh_tokens',
    'DELETE FROM oauth_par_requests',
    'DELETE FROM app_sessions'
  ], "write");
}
