import 'dotenv/config';
import http from 'http';
import axios from 'axios';
import { db, create } from './db.js';
import app, { wss } from './server.js';
import { setUpRepo } from './repo.js';

const PORT = process.env.PORT || 3000;

const RELAY_URL = process.env.RELAY_URL || 'https://bsky.network';

function normalizeHostname(value) {
  const trimmed = (value || '').trim();
  if (!trimmed) return '';

  try {
    return new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`).host;
  } catch {
    return trimmed.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  }
}

async function resolveRelayHostname() {
  const explicitHost = normalizeHostname(process.env.DOMAIN);
  if (explicitHost) {
    return explicitHost;
  }

  const did = (process.env.PDS_DID || '').trim();
  if (did.startsWith('did:plc:')) {
    try {
      const res = await axios.get(`https://plc.directory/${did}`, { timeout: 5000 });
      const endpoint = res.data?.service?.find((service) => (
        service?.id === '#atproto_pds' || service?.type === 'AtprotoPersonalDataServer'
      ))?.serviceEndpoint;
      const plcHost = normalizeHostname(endpoint);
      if (plcHost) {
        return plcHost;
      }
    } catch (err) {
      console.warn(`Failed to resolve PDS host from PLC for ${did}:`, err.message);
    }
  }

  return normalizeHostname(process.env.HANDLE);
}

async function pingRelay(hostname) {
  console.log(`Pinging relay ${RELAY_URL} to crawl ${hostname}...`);
  await axios.post(`${RELAY_URL}/xrpc/com.atproto.sync.requestCrawl`, { hostname });
  console.log('Relay notified successfully.');
  return { success: true };
}

// Validation & Initialization
if (!process.env.HANDLE) throw new Error('Missing HANDLE environment variable');
if (!process.env.PDS_DID) throw new Error('Missing PDS_DID environment variable');
if (!process.env.PRIVATE_KEY) throw new Error('Missing PRIVATE_KEY environment variable');
if (!process.env.OAUTH_ES256K_PRIVATE_KEY) throw new Error('Missing OAUTH_ES256K_PRIVATE_KEY environment variable');
if (!process.env.OAUTH_RS256_PRIVATE_KEY) throw new Error('Missing OAUTH_RS256_PRIVATE_KEY environment variable');
if (!process.env.PASSWORD) throw new Error('Missing PASSWORD environment variable');
if (!process.env.TURSO_DATABASE_URL) throw new Error('Missing TURSO_DATABASE_URL environment variable');

console.log('Initializing PDS...');
await create();
await setUpRepo();
console.log('Initialization complete.');

const server = http.createServer(app);

// Handle WebSocket upgrades for the firehose
server.on('upgrade', (request, socket, head) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  if (url.pathname.startsWith('/xrpc/com.atproto.sync.subscribeRepos')) {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});

server.listen(PORT, () => {
  console.log(`Minimal PDS listening on port ${PORT}`);
  
  // Proactively ping relay on startup
  resolveRelayHostname()
    .then((hostname) => pingRelay(hostname))
    .catch(err => {
      console.warn('Initial relay ping failed:', err.message);
    });
});
