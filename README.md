# Personal PDS (AT Protocol)

A lightweight, modular, single-user AT Protocol Personal Data Server (PDS) built with Node.js, Express 5, and Turso. Optimized for self-hosting your identity and data on the Bluesky network.

## Key Features

- **Modular Architecture**: Clean separation of concerns between core server, OAuth flow, proxy logic, and repository management.
- **Single-User Design**: Identity and configuration are managed via environment variables and initialized at startup.
- **Robust OAuth 2.1**: Full implementation of ATProto OAuth, including DPoP token binding and Pushed Authorization Requests (PAR).
- **FedCM + IndieAuth IdP**: Browser-facing IdP endpoints, Login Status accounts push, IdP Registration, and IndieAuth-style FedCM code exchange.
- **Turso Integration**: Scalable, edge-ready storage using LibSQL.
- **Real-time Firehose**: Canonical `dag-cbor` event streaming for indexing by the Bluesky network.
- **Express 5 Native**: Leverages native async error handling for cleaner, more reliable middleware and handlers.

## Architecture & Components

- **`src/server.js`**: Core route aggregator and protocol handlers.
- **`src/oauth.js`**: Complete OAuth/OIDC implementation (Metadata, PAR, Authorize, Token, JWKS).
- **`src/auth.js`**: Authentication middleware and token validation (Bearer & DPoP).
- **`src/repo.js`**: ATProto Repository management (MST, Blockstore, CAR exports).
- **`src/proxy.js`**: Intelligent XRPC proxying with Service Authentication for external AppViews.
- **`src/sequencer.js`**: Firehose event sequencing and WebSocket broadcasting.
- **`src/admin.js`**: Web-based dashboard for PDS monitoring and management.

## Implemented XRPC Handlers

### com.atproto (Core)
- `server.describeServer`: Server metadata.
- `server.getServiceContext`: Service identity resolution.
- `server.createSession` / `refreshSession`: Legacy session management.
- `server.getSession` / `getAccount`: Authenticated account details.
- `server.checkAccountStatus`: Account health and repo head.
- `identity.resolveDid` / `resolveHandle`: Local and proxied identity resolution.
- `repo.createRecord` / `putRecord` / `deleteRecord`: Data modifications.
- `repo.applyWrites`: Batch data operations.
- `repo.listRecords` / `getRecord` / `describeRepo`: Data retrieval.
- `repo.uploadBlob` / `sync.getBlob`: Blob storage and retrieval.
- `sync.getRepo` / `getCheckout` / `getBlocks`: Repository synchronization.
- `sync.getHead` / `getLatestCommit` / `getRepoStatus`: Head and sequence tracking.
- `sync.subscribeRepos`: Firehose (WebSocket).

### app.bsky (Bluesky)
- `app.bsky.actor.getPreferences` / `putPreferences`: Local preference storage.
- All other `app.bsky.*` methods are intelligently proxied to the configured AppView with Service Auth.

### OAuth / OIDC
- `POST /oauth/par`: Pushed Authorization Request.
- `GET/POST /oauth/authorize`: Authorization UI and logic.
- `POST /oauth/token`: Token exchange (Code & Refresh).
- `GET /.well-known/oauth-authorization-server`: OAuth metadata.
- `GET /.well-known/oauth-protected-resource`: Resource server metadata.
- `GET /.well-known/openid-configuration`: OIDC discovery.
- `GET /.well-known/jwks.json`: Public keys for token verification.

### FedCM / IndieAuth
- `GET /.well-known/web-identity`: FedCM discovery.
- `GET /config.json`: FedCM IdP config.
- `GET /profile`: Public IndieAuth profile URL with `rel="indieauth-metadata"`.
- `GET /avatar`: User avatar with cross-origin image headers for FedCM/Login Status and IndieAuth profile responses.
- `GET /logo`: FedCM branding icon with cross-origin image headers.
- `GET/POST /login`: Browser login page for Login Status + IdP registration.
- `POST /logout`: Browser logout page.
- `POST /assertion`: FedCM assertion endpoint returning IndieAuth-style assertion payload.
- `POST /disconnect`: FedCM disconnect endpoint.

## Database Schema (Turso/SQLite)

The PDS uses a streamlined schema for repository data, identity, and OAuth state:

- `repo_blocks`: Content-addressed storage for repository MST nodes and records (`cid`, `block`).
- `blobs`: User-uploaded media and files (`cid`, `did`, `mime_type`, `content`, `created_at`).
- `sequencer`: Firehose event log for relay indexing (`seq`, `did`, `type`, `event`, `time`).
- `preferences`: Local user preferences and birthdate (`key`, `value`).
- `sessions`: Legacy session tracking (`id`, `handle`, `did`, `expires_at`).
- `oauth_codes`: Temporary authorization codes (`code`, `client_id`, `redirect_uri`, `scope`, `did`, `dpop_jwk`, `expires_at`).
- `oauth_refresh_tokens`: Long-lived refresh tokens (`token`, `client_id`, `did`, `scope`, `dpop_jwk`, `expires_at`).
- `oauth_par_requests`: Pending authorization requests (`request_uri`, `client_id`, `request_data`, `expires_at`).

## Setup & Deployment

### 1. Generate PDS Identity Keys
Run the following command to generate a valid Secp256k1 private key for your PDS identity and repo signing:
```bash
npm run gen-key pds.your-domain.com
```

### 2. Generate OAuth Signing Keys
If you want OAuth signing keys to be separate from your repo/DID key, generate them with:
```bash
npm run gen-oauth-keys
```

This prints:
- `OAUTH_ES256K_PRIVATE_KEY` for ES256K-signed OAuth artifacts
- `OAUTH_RS256_PRIVATE_KEY` for RS256 JARM compatibility

### 3. Environment Configuration
Create a `.env` file and populate it with the values generated above, along with your other details:
- `HANDLE`: Your ATProto account handle (e.g., `your-domain.com`).
- `DOMAIN`: Public hostname of the PDS service itself (e.g., `pds.your-domain.com`). It is used for PLC relay crawl notifications and as the issuer origin when publishing a `HandleVerification` service.
- `PDS_DID`: Your primary account DID (from `gen-key` or a registered `did:plc`).
- `PRIVATE_KEY`: Your repo/DID signing key generated by `gen-key`.
- `PLC_ROTATION_KEY`: Your PLC DID rotation key, needed by the admin dashboard to publish DID document service changes.
- `OAUTH_ES256K_PRIVATE_KEY`: Required separate ES256K OAuth signing key generated by `gen-oauth-keys`.
- `OAUTH_RS256_PRIVATE_KEY`: Required RSA OAuth signing key generated by `gen-oauth-keys`.
- `PASSWORD`: Your PDS login password.
- `TURSO_DATABASE_URL`: Your Turso connection string.
- `TURSO_AUTH_TOKEN`: Your Turso auth token.

If `HANDLE` and `DOMAIN` differ, relay crawl notifications and the issuer service use `DOMAIN`, not the handle domain.

### Handle Verification issuer

Set `DOMAIN` to the canonical public PDS hostname (for example, `pds.your-domain.com`), configure `PLC_ROTATION_KEY`, then use the dashboard's PLC panel to publish the `HandleVerification` service. The issuer serves metadata at `/.well-known/handle-verification`, issuance at `/hvp/issuance`, and signing keys at `/hvp/jwks`. It creates an ephemeral Ed25519 signing key when the Node process starts; each restart rotates the key, so HVTs issued before a restart will no longer verify. HVP issuance requires an active browser session and signs each token only after checking the handle resolution, DID back-link, and authorized issuer service.

### 4. Initialization
Initialization happens automatically on the first run of the server.
```bash
npm start
```

### 5. Setup Profile (Optional)
To set up your initial Bluesky profile and birthdate:
```bash
npm run setup-profile "Your Name" "Your Bio" YYYY-MM-DD
```

### 6. Testing
```bash
npm test
```

### 7. Browser E2E (FedCM)
Install Chromium once:
```bash
npm run test:e2e:install
```

Run the FedCM browser test:
```bash
npm run test:e2e:fedcm
```

Run the full test suite, including the FedCM browser e2e:
```bash
npm test
```

How the e2e test works:
- It starts this PDS as the IdP and a tiny local RP in the same test process.
- The test logs into the IdP at `/login`, submits the PDS password automatically, and waits for the post-login page to push `navigator.login.setStatus(..., { accounts, apiConfig })` successfully.
- The RP then calls `navigator.credentials.get(...)` with the IdP's explicit `configURL` and `type: "indieauth"`, relying on the pushed Login Status account data rather than an `/accounts` endpoint.
- Playwright uses Chromium CDP `FedCm.*` commands to accept the browser-mediated FedCM dialog.
- The RP parses the assertion JSON, discovers the metadata endpoint, exchanges the code at the token endpoint, and verifies that the returned `me` URL points back to the same IndieAuth metadata endpoint.
- The test also seeds a real `app.bsky.actor.profile` record, then verifies that the exchanged profile photo URL resolves to a loadable image.

Notes:
- The e2e test uses a single persistent Chromium context with multiple pages. Separate Playwright browser contexts would isolate the IdP cookies and registration state, which breaks FedCM.
- The stable automated path uses the IdP's explicit `configURL`. The registration-only `configURL: "any"` flow is intentionally not part of the default suite right now.
- If the browser flow fails, the test prints browser console logs, CDP FedCM events, and IdP route hits so it is easier to see whether the failure happened before login-status propagation or `/assertion`.

## License
Apache License 2.0
