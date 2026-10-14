import { randomBytes } from 'crypto';
import { db } from './db.js';
import { signJwt, verifyToken } from './auth.js';

// Legacy (app-password style) sessions used by bsky.app and other clients via
// com.atproto.server.createSession / refreshSession / deleteSession.
//
// - Access tokens are short-lived (2h) and carry a session id (`sid`). The auth
//   middleware checks that the session still exists, so deleteSession revokes
//   them immediately.
// - Refresh tokens are long-lived (90 days, sliding), have their own scope
//   (`com.atproto.refresh`) so they can never be used as access tokens, and are
//   rotated on every use. The previous refresh token stays valid for a short
//   grace period so that concurrent refreshes (e.g. multiple tabs) don't log
//   the user out.

export const ACCESS_TOKEN_TTL_SECONDS = 2 * 60 * 60;
export const REFRESH_TOKEN_TTL_SECONDS = 90 * 24 * 60 * 60;
export const REFRESH_REUSE_GRACE_SECONDS = 2 * 60;
export const REFRESH_SCOPE = 'com.atproto.refresh';

const now = () => Math.floor(Date.now() / 1000);
const newId = () => randomBytes(16).toString('hex');

// The app_sessions table is created in db.js create().

const signAccessToken = (did, handle, sid) => {
  const iat = now();
  return signJwt({ sub: did, handle, scope: 'atproto', sid, iat, exp: iat + ACCESS_TOKEN_TTL_SECONDS });
};

const signRefreshToken = (did, sid, jti, exp) => signJwt({
  sub: did, scope: REFRESH_SCOPE, sid, jti, iat: now(), exp,
});

export async function createAppSession(did, handle) {
  const sid = newId();
  const jti = newId();
  const createdAt = now();
  const expiresAt = createdAt + REFRESH_TOKEN_TTL_SECONDS;

  // Opportunistically clean up expired sessions.
  await db.execute({ sql: 'DELETE FROM app_sessions WHERE expires_at <= ?', args: [createdAt] });
  await db.execute({
    sql: 'INSERT INTO app_sessions (sid, did, handle, refresh_jti, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
    args: [sid, did, handle, jti, createdAt, expiresAt],
  });

  return {
    accessJwt: await signAccessToken(did, handle, sid),
    refreshJwt: await signRefreshToken(did, sid, jti, expiresAt),
  };
}

/** Returns true if the session referenced by an access token still exists. */
export async function isAppSessionActive(sid) {
  if (typeof sid !== 'string' || !sid) return false;
  const res = await db.execute({
    sql: 'SELECT 1 FROM app_sessions WHERE sid = ? AND expires_at > ?',
    args: [sid, now()],
  });
  return res.rows.length > 0;
}

/**
 * Validates a refresh token and returns { payload, row, isCurrent } or null.
 */
async function loadRefreshToken(token) {
  const payload = await verifyToken(token);
  const pdsDid = (process.env.PDS_DID || '').trim();
  if (!payload || payload.scope !== REFRESH_SCOPE || payload.sub !== pdsDid || !payload.sid || !payload.jti) {
    return null;
  }
  const res = await db.execute({
    sql: 'SELECT * FROM app_sessions WHERE sid = ? AND expires_at > ?',
    args: [payload.sid, now()],
  });
  const row = res.rows[0];
  if (!row) return null;
  if (payload.jti === row.refresh_jti) return { payload, row, isCurrent: true };
  if (payload.jti === row.prev_refresh_jti && row.prev_valid_until && now() < Number(row.prev_valid_until)) {
    return { payload, row, isCurrent: false };
  }
  return null;
}

/** Rotates a refresh token. Returns new { accessJwt, refreshJwt, did, handle } or null. */
export async function refreshAppSession(token) {
  const loaded = await loadRefreshToken(token);
  if (!loaded) return null;
  const { row, isCurrent } = loaded;

  if (!isCurrent) {
    // Reuse of the previous token within the grace window (concurrent refresh):
    // don't rotate again, just hand out the current refresh token.
    return {
      did: row.did,
      handle: row.handle,
      accessJwt: await signAccessToken(row.did, row.handle, row.sid),
      refreshJwt: await signRefreshToken(row.did, row.sid, row.refresh_jti, Number(row.expires_at)),
    };
  }

  const nextJti = newId();
  const expiresAt = now() + REFRESH_TOKEN_TTL_SECONDS;
  const update = await db.execute({
    sql: `UPDATE app_sessions
          SET refresh_jti = ?, prev_refresh_jti = ?, prev_valid_until = ?, expires_at = ?
          WHERE sid = ? AND refresh_jti = ?`,
    args: [nextJti, row.refresh_jti, now() + REFRESH_REUSE_GRACE_SECONDS, expiresAt, row.sid, row.refresh_jti],
  });
  if (update.rowsAffected === 0) {
    // Lost a race with a concurrent refresh; retry once against the new state.
    return refreshAppSession(token);
  }

  return {
    did: row.did,
    handle: row.handle,
    accessJwt: await signAccessToken(row.did, row.handle, row.sid),
    refreshJwt: await signRefreshToken(row.did, row.sid, nextJti, expiresAt),
  };
}

/** Deletes the session referenced by a refresh token. Returns true if deleted. */
export async function deleteAppSession(token) {
  const loaded = await loadRefreshToken(token);
  if (!loaded) return false;
  await db.execute({ sql: 'DELETE FROM app_sessions WHERE sid = ?', args: [loaded.row.sid] });
  return true;
}
