import jwt from 'jsonwebtoken';
import { createHash, createPublicKey, createPrivateKey, createECDH, verify as cryptoVerify, randomBytes } from 'crypto';
import * as cryptoAtp from '@atproto/crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { getOauthEs256kKeypair, getOauthEs256kPrivateKeyHex } from './oauth-keys.js';

export async function createToken(did, handle) {
  const privKeyHex = getOauthEs256kPrivateKeyHex();
  if (!privKeyHex) throw new Error('No PDS private key');
  
  const payload = { 
    sub: did, 
    handle, 
    scope: 'atproto',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (24 * 3600)
  };

  const header = { typ: 'JWT', alg: 'ES256K' };
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const data = Buffer.from(`${headerB64}.${payloadB64}`);

  const keypair = await getOauthEs256kKeypair();
  const sig = await keypair.sign(data);
  const sigB64 = Buffer.from(sig).toString('base64url');

  return `${headerB64}.${payloadB64}.${sigB64}`;
}

export async function createServiceAuthToken(aud, lxm, sub, exp = null) {
  const privKeyHex = process.env.PRIVATE_KEY;
  const pdsDid = (process.env.PDS_DID || '').trim();
  if (!privKeyHex) throw new Error('No PDS private key');
  if (!pdsDid) throw new Error('No PDS DID');

  const payload = {
    iss: pdsDid,
    sub,
    aud: aud.split('#')[0],
    lxm,
    iat: Math.floor(Date.now() / 1000),
    exp: exp || (Math.floor(Date.now() / 1000) + 60),
    jti: randomBytes(16).toString('hex'),
  };

  const header = { typ: 'JWT', alg: 'ES256K' };
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const data = Buffer.from(`${headerB64}.${payloadB64}`);

  const keypair = await cryptoAtp.Secp256k1Keypair.import(new Uint8Array(Buffer.from(privKeyHex, 'hex')));
  const sig = await keypair.sign(data);
  const sigB64 = Buffer.from(sig).toString('base64url');

  return `${headerB64}.${payloadB64}.${sigB64}`;
}

export async function verifyToken(token) {
  try {
    if (!token) return null;
    const [headerB64, payloadB64, sigB64] = token.split('.');
    if (!headerB64 || !payloadB64 || !sigB64) return null;
    
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    
    if (header.alg !== 'ES256K') return null;
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;

    const data = Buffer.from(`${headerB64}.${payloadB64}`);
    const signature = Buffer.from(sigB64, 'base64url');

    const candidateKeys = [];
    const oauthKeyHex = getOauthEs256kPrivateKeyHex();
    if (oauthKeyHex) {
      candidateKeys.push(oauthKeyHex);
    }
    const repoKeyHex = process.env.PRIVATE_KEY;
    if (repoKeyHex && repoKeyHex !== oauthKeyHex) {
      candidateKeys.push(repoKeyHex);
    }

    for (const keyHex of candidateKeys) {
      const kp = await cryptoAtp.Secp256k1Keypair.import(new Uint8Array(Buffer.from(keyHex, 'hex')));
      const isVerified = await cryptoAtp.verifySignature(kp.did(), data, signature);
      if (isVerified) {
        return payload;
      }
    }

    return null;
  } catch (err) {
    return null;
  }
}

export function getJkt(jwk) {
  const { kty, n, e, crv, x, y } = jwk;
  let components;
  if (kty === 'RSA') {
    components = { e, kty, n };
  } else if (kty === 'EC') {
    components = { crv, kty, x, y };
  } else if (kty === 'OKP') {
    components = { crv, kty, x };
  } else {
    throw new Error('Unsupported JWK kty');
  }
  const json = JSON.stringify(components);
  return createHash('sha256').update(json).digest('base64url');
}

export async function validateDpop(req, access_token = null) {
  const dpop = req.headers.dpop;
  if (!dpop) return { jkt: null, jwk: null };

  const requestId = req.get('x-request-id') || 'no-request-id';
  const decoded = jwt.decode(dpop, { complete: true });
  if (!decoded || !decoded.header || !decoded.header.jwk) {
    throw new Error('Invalid DPoP header');
  }

  const jwk = decoded.header.jwk;
  const jkt = getJkt(jwk);
  const { htu, htm } = decoded.payload || {};
  const protocol = req.user?.protocol || (req.protocol === 'https' || process.env.NODE_ENV === 'production' ? 'https' : 'http');
  const host = req.user?.host || req.get('host');
  const path = (req.originalUrl || req.url).split('?')[0];
  const expectedHtu = `${protocol}://${host}${path}`;

  console.log('[DPOP] Proof received', {
    requestId,
    path,
    alg: decoded.header.alg,
    typ: decoded.header.typ,
    kid: decoded.header.kid || null,
    jwk_kty: jwk.kty,
    jwk_crv: jwk.crv || null,
    htm,
    htu,
    expectedHtu,
    hasAth: Boolean(decoded.payload?.ath),
    accessTokenBound: Boolean(access_token),
  });

  // Verify DPoP signature using the JWK
  try {
    if (jwk.kty === 'EC' && jwk.crv === 'secp256k1') {
      const publicKeyBytes = new Uint8Array(Buffer.concat([Buffer.from([0x04]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]));
      const [headerB64, payloadB64, sigB64] = dpop.split('.');
      const data = Buffer.from(`${headerB64}.${payloadB64}`);
      const signature = Buffer.from(sigB64, 'base64url');
      const msgHash = createHash('sha256').update(data).digest();
      // DPoP uses JOSE signatures, so be tolerant of valid high-S secp256k1 signatures.
      const verified = secp256k1.verify(signature, msgHash, publicKeyBytes, {
        format: 'compact',
        lowS: false,
      });
      if (!verified) throw new Error('DPoP signature verification failed');
      console.log('[DPOP] secp256k1 signature verified', { requestId, path });
    } else {
      const publicKey = createPublicKey({ key: jwk, format: 'jwk' });
      // jsonwebtoken handles the signature format conversion (raw vs DER) for EC keys
      jwt.verify(dpop, publicKey, { algorithms: ['ES256', 'RS256'] });
      console.log('[DPOP] JOSE signature verified', {
        requestId,
        path,
        alg: decoded.header.alg,
        jwk_kty: jwk.kty,
        jwk_crv: jwk.crv || null,
      });
    }
  } catch (err) {
    console.error('[DPOP] Signature verification failed', {
      requestId,
      path,
      alg: decoded.header.alg,
      jwk_kty: jwk.kty,
      jwk_crv: jwk.crv || null,
      message: err.message,
    });
    throw new Error(`DPoP signature verification failed: ${err.message}`);
  }

  // Basic DPoP claim verification
  if (htm !== req.method) {
    throw new Error('DPoP htm mismatch');
  }

  if (htu !== expectedHtu) {
    // Be lenient with trailing slashes
    const normalizedHtu = htu.endsWith('/') ? htu.slice(0, -1) : htu;
    const normalizedExpected = expectedHtu.endsWith('/') ? expectedHtu.slice(0, -1) : expectedHtu;
    if (normalizedHtu !== normalizedExpected) {
      console.error(`DPoP htu mismatch debug: expected ${expectedHtu}, got ${htu}`);
      throw new Error(`DPoP htu mismatch: expected ${expectedHtu}, got ${htu}`);
    }
  }

  // If access_token is provided, verify it's bound to this jkt
  if (access_token) {
    const payload = await verifyToken(access_token);
    if (!payload || !payload.cnf || payload.cnf.jkt !== jkt) {
      throw new Error('Token binding mismatch');
    }
  }

  console.log('[DPOP] Proof accepted', { requestId, path, jkt });
  return { jkt, jwk };
}

/**
 * verifyToken() only checks the signature, and several different kinds of JWTs
 * are signed with the same keys (legacy session tokens, OAuth access tokens,
 * OIDC id_tokens, JARM responses and outbound service-auth tokens). Only the
 * first two may be used to authenticate as the account owner, so make sure the
 * payload actually looks like a user access token for this PDS's account.
 */
export function isUserAccessToken(payload) {
  if (!payload || typeof payload !== 'object') return false;
  const pdsDid = (process.env.PDS_DID || '').trim();
  if (!pdsDid || payload.sub !== pdsDid) return false;
  // Service-auth tokens carry a lexicon method binding; never accept them here.
  if (payload.lxm) return false;
  // Session / OAuth access tokens always carry a scope; id_tokens and JARM
  // responses do not.
  if (typeof payload.scope !== 'string' || payload.scope.trim() === '') return false;
  return true;
}

export const auth = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.log(`Auth failed: No Authorization header for ${req.url}`);
    return res.status(401).json({ error: 'AuthenticationRequired' });
  }
  const [type, token] = authHeader.split(' ');
  const jwtToken = (type === 'Bearer' || type === 'DPoP') ? token : type;
  
  if (!jwtToken) {
    console.log(`Auth failed: Empty token for ${req.url}`);
    return res.status(401).json({ error: 'AuthenticationRequired', message: 'Token missing' });
  }
  
  if (type === 'DPoP') {
    let jkt;
    try {
      ({ jkt } = await validateDpop(req, jwtToken));
    } catch (err) {
      console.log(`Auth failed: DPoP validation failed for ${req.url}: ${err.message}`);
      res.setHeader('WWW-Authenticate', `DPoP error="invalid_dpop_proof", error_description="${err.message.replace(/"/g, "'")}"`);
      return res.status(401).json({ error: 'invalid_dpop_proof', message: err.message });
    }
    const payload = await verifyToken(jwtToken);
    if (!payload || payload.cnf?.jkt !== jkt) {
      return res.status(401).json({ error: 'InvalidToken', message: 'DPoP binding mismatch' });
    }
    if (!isUserAccessToken(payload)) {
      console.log(`Auth failed: Token is not a user access token for ${req.url}`);
      return res.status(401).json({ error: 'InvalidToken' });
    }
    if (!req.user) req.user = {};
    req.user.auth = payload;
    return next();
  }

  const payload = await verifyToken(jwtToken);
  if (!payload || !isUserAccessToken(payload)) {
    console.log(`Auth failed: Invalid token for ${req.url}`);
    return res.status(401).json({ error: 'InvalidToken' });
  }
  // DPoP-bound (OAuth) access tokens must not be usable as plain bearer tokens.
  if (payload.cnf) {
    console.log(`Auth failed: DPoP-bound token used without DPoP for ${req.url}`);
    return res.status(401).json({ error: 'InvalidToken', message: 'DPoP-bound token requires DPoP authorization' });
  }
  if (!req.user) req.user = {};
  req.user.auth = payload;
  next();
};

export const oauth = (requiredScope) => (req, res, next) => {
  if (!req.user?.auth) {
    return res.status(401).json({ error: 'AuthenticationRequired' });
  }
  
  const scope = req.user.auth.scope || '';
  const scopes = scope.split(' ');
  
  if (scopes.includes('atproto')) {
    return next(); // 'atproto' is full access
  }
  
  if (scopes.includes(requiredScope)) {
    return next();
  }
  
  console.log(`OAuth scope check failed for ${req.url}. Required: ${requiredScope}, Got: ${scope}`);
  res.status(403).json({ 
    error: 'InsufficientScope', 
    message: `This operation requires the '${requiredScope}' scope.` 
  });
};
