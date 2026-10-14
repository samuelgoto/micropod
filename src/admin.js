import express from 'express';
import { db, destroy } from './db.js';
import * as cbor from '@ipld/dag-cbor';
import { sequencer } from './sequencer.js';
import { setUpRepo, getRootCid, acquireRepoWriteLock } from './repo.js';
import { escapeHtml, verifyPassword } from './util.js';
import { getLoginUrl } from './session.js';
import { buildFedCmAccount, getConfigUrl } from './fedcm.js';

const router = express.Router();

function requireBrowserSession(req, res, next) {
  if (req.session) {
    return next();
  }

  if (req.method === 'GET') {
    return res.redirect(getLoginUrl(req.originalUrl || '/', { autoReturn: true }));
  }

  return res.status(401).send('<h1>Authentication required</h1><p>Please sign in at <a href="/login">/login</a> first.</p>');
}

router.get('/', requireBrowserSession, async (req, res) => {
  const user = req.user;
  const account = await buildFedCmAccount(req);
  const blockCountRes = await db.execute('SELECT count(*) as count FROM repo_blocks');
  const eventCountRes = await db.execute('SELECT count(*) as count FROM sequencer');
  const subscriberCount = sequencer.getSubscriberCount();
  const rootCid = await getRootCid();
  const configUrl = getConfigUrl(req);
  const avatarHtml = account.picture
    ? `<img class="profile-avatar" src="${escapeHtml(account.picture)}" alt="${escapeHtml(account.name)}">`
    : '<div class="profile-avatar fallback" aria-hidden="true"></div>';

  // Get last 10 events
  const lastEventsRes = await db.execute("SELECT * FROM sequencer ORDER BY seq DESC LIMIT 10");
  const events = lastEventsRes.rows.map(row => {
    try {
      const evt = cbor.decode(new Uint8Array(row.event));
      return {
        seq: row.seq,
        time: row.time,
        ops: evt.ops || []
      };
    } catch (e) {
      return { seq: row.seq, time: row.time, ops: [] };
    }
  });

  const html = `
<!DOCTYPE html>
<html>
<head>
    <title>Personal PDS Dashboard</title>
    <link rel="icon" href="/favicon.ico" sizes="any">
    <style>
        :root {
            color-scheme: light;
            --bg: #f3f5f7;
            --card: #ffffff;
            --ink: #111827;
            --muted: #4b5563;
            --line: #d1d5db;
            --accent: #0f172a;
            --accent-soft: #e5e7eb;
            --ok: #166534;
            --ok-bg: #dcfce7;
            --warn: #b91c1c;
            --warn-bg: #fee2e2;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: radial-gradient(circle at top, #dbeafe, #f8fafc 45%);
            color: var(--ink);
            min-height: 100vh;
            margin: 0;
            padding: 24px;
        }
        main {
            width: min(1080px, 100%);
            margin: 0 auto;
        }
        .hero {
            background: var(--card);
            border: 1px solid var(--line);
            border-radius: 18px;
            padding: 28px;
            box-shadow: 0 20px 60px rgba(15, 23, 42, 0.08);
            margin-bottom: 20px;
        }
        .eyebrow {
            margin: 0 0 6px;
            color: var(--muted);
            font-size: 0.95rem;
        }
        h1 {
            margin: 0 0 10px;
            font-size: 2rem;
            color: var(--ink);
        }
        .hero p {
            margin: 0;
            color: var(--muted);
            line-height: 1.5;
        }
        .hero-actions {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-top: 18px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 20px;
        }
        .card {
            background: var(--card);
            border: 1px solid var(--line);
            border-radius: 18px;
            padding: 24px;
            box-shadow: 0 20px 60px rgba(15, 23, 42, 0.08);
            margin-bottom: 20px;
        }
        h2 {
            margin: 0 0 16px;
            font-size: 1.15rem;
        }
        .stat {
            display: flex;
            justify-content: space-between;
            gap: 16px;
            border-bottom: 1px solid var(--line);
            padding: 10px 0;
        }
        .stat:last-child {
            border-bottom: none;
        }
        .label {
            font-weight: 600;
        }
        .value {
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            color: var(--muted);
            text-align: right;
            word-break: break-word;
        }
        .status-ok {
            color: var(--ok);
            font-weight: 700;
        }
        .status-warn {
            color: var(--warn);
            font-weight: 700;
        }
        .actions {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-top: 16px;
        }
        .profile-panel {
            display: flex;
            gap: 18px;
            align-items: center;
            margin-bottom: 16px;
        }
        .profile-avatar {
            width: 72px;
            height: 72px;
            border-radius: 999px;
            object-fit: cover;
            background: #dbeafe;
            border: 1px solid var(--line);
        }
        .profile-avatar.fallback {
            display: block;
            background: linear-gradient(135deg, #bfdbfe, #e2e8f0);
        }
        .profile-name {
            margin: 0;
            font-size: 1.2rem;
        }
        .profile-handle {
            margin: 4px 0 0;
            color: var(--muted);
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        }
        .profile-note {
            margin: 0 0 16px;
            color: var(--muted);
            line-height: 1.5;
        }
        a, button {
            appearance: none;
            border: 0;
            border-radius: 999px;
            padding: 10px 16px;
            font: inherit;
            text-decoration: none;
            cursor: pointer;
        }
        button, .button-primary {
            background: var(--accent);
            color: #fff;
        }
        button.secondary, .button-secondary {
            background: var(--accent-soft);
            color: var(--ink);
        }
        button.danger {
            background: var(--warn);
            color: #fff;
        }
        .activity-item {
            padding: 12px 0;
            border-bottom: 1px solid var(--line);
            font-size: 0.95rem;
        }
        .activity-item:last-child {
            border-bottom: none;
        }
        .activity-time {
            color: #6b7280;
            font-size: 0.85rem;
        }
        .op-tag {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            margin-right: 8px;
        }
        .op-create {
            background: #dcfce7;
            color: #166534;
        }
        .op-update {
            background: #fef3c7;
            color: #92400e;
        }
        .op-delete {
            background: #fee2e2;
            color: #991b1b;
        }
        #action-result,
        #fedcm-status {
            margin-top: 14px;
            padding: 14px;
            border: 1px solid var(--line);
            border-radius: 12px;
            background: #f8fafc;
            color: var(--muted);
            white-space: pre-wrap;
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            display: none;
        }
        #fedcm-status {
            display: block;
        }
        .danger-zone {
            border: 1px solid #fecaca;
            background: #fff5f5;
        }
        .danger-zone p {
            color: var(--muted);
        }
        .danger-form {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-top: 16px;
        }
        input[type="password"] {
            flex: 1 1 240px;
            border: 1px solid var(--line);
            border-radius: 12px;
            padding: 12px 14px;
            font: inherit;
            background: #fff;
        }
        @media (max-width: 800px) {
            .grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
  <main>
    <section class="hero">
        <p class="eyebrow">Welcome to your PDS</p>
        <h1>Personal PDS Dashboard</h1>
        <p>Inspect repo health, browser identity state, and recent sequencer activity from the same session-backed control panel used by the rest of the PDS.</p>
        <div class="hero-actions">
            <a class="button-secondary" href="/logout">Log out</a>
        </div>
    </section>

    <div class="grid">
        <div class="card">
            <h2>Identity</h2>
            <div class="stat"><span class="label">Handle</span><span class="value">${user.handle}</span></div>
            <div class="stat"><span class="label">DID</span><span class="value">${user.did}</span></div>
            <div class="stat"><span class="label">PDS Domain</span><span class="value">${user.host}</span></div>
        </div>

        <div class="card">
            <h2>Published Profile</h2>
            <div class="profile-panel">
                ${avatarHtml}
                <div>
                    <p class="profile-name">${escapeHtml(account.name)}</p>
                    <p class="profile-handle">${escapeHtml(account.email || `@${user.handle}`)}</p>
                </div>
            </div>
            <p class="profile-note">This is the identity metadata the PDS publishes from <code>app.bsky.actor.profile</code> and uses for FedCM and IndieAuth.</p>
            <div class="stat"><span class="label">Display Name</span><span class="value">${escapeHtml(account.name)}</span></div>
            <div class="stat"><span class="label">Handle</span><span class="value">${escapeHtml(account.email || `@${user.handle}`)}</span></div>
            <div class="stat"><span class="label">Profile URL</span><span class="value">${escapeHtml(account.id)}</span></div>
            <div class="stat"><span class="label">Avatar URL</span><span class="value">${escapeHtml(account.picture || 'Not set')}</span></div>
        </div>

        <div class="card">
            <h2>Network & Status</h2>
            <div class="stat"><span class="label">PDS Status</span><span class="value status-ok">Online</span></div>
            <div class="stat"><span class="label">Relay Connections</span><span class="value ${subscriberCount > 0 ? 'status-ok' : 'status-warn'}">${subscriberCount}</span></div>
            <div class="stat"><span class="label">Repo Head</span><span class="value" style="font-size: 0.8em;">${rootCid}</span></div>
            <div class="actions">
                <button class="secondary" onclick="runAction('/xrpc/com.atproto.server.describeServer')">Self-Check</button>
                <button onclick="runAction('/xrpc/com.atproto.server.activateAccount', 'POST')">Activate Account</button>
            </div>
            <div id="action-result"></div>
        </div>
    </div>

    <div class="card">
        <h2>Recent Activity</h2>
        <div id="activity-feed">
            ${events.length === 0 ? '<p>No activity yet.</p>' : events.map(e => `
                <div class="activity-item">
                    <strong>Seq ${e.seq}</strong> <span class="activity-time">${new Date(e.time).toLocaleTimeString()}</span><br/>
                    ${e.ops.map(op => `
                        <span class="op-tag op-${op.action}">${op.action}</span> 
                        <span class="value">${op.path}</span>
                    `).join('<br/>')}
                </div>
            `).join('')}
        </div>
    </div>

    <div class="card">
        <h2>System & Storage</h2>
        <div class="stat"><span class="label">Total Repo Blocks</span><span class="value">${blockCountRes.rows[0].count}</span></div>
        <div class="stat"><span class="label">Event Log Size</span><span class="value">${eventCountRes.rows[0].count}</span></div>
        <div class="stat"><span class="label">Node.js</span><span class="value">${process.version}</span></div>
        <div class="stat"><span class="label">Database</span><span class="value">Turso (libSQL)</span></div>
    </div>

    <div class="card">
        <h2>Browser Identity</h2>
        <p>Register this PDS as a FedCM IndieAuth identity provider in the current browser.</p>
        <div class="actions">
            <button id="register-fedcm" class="secondary" type="button">Register PDS</button>
            <button id="unregister-fedcm" class="secondary" type="button">Unregister PDS</button>
        </div>
        <div id="fedcm-status">Idle</div>
    </div>

    <div class="card danger-zone">
        <h2>Danger Zone</h2>
        <p>Wiping the PDS will delete all posts, follows, likes, and profile data. This cannot be undone.</p>
        <form class="danger-form" action="/debug/reset" method="POST" onsubmit="return confirm('PERMANENTLY DELETE ALL DATA? This is your last warning.')">
            <input type="password" name="password" placeholder="PDS Password" required>
            <button type="submit" class="danger">Wipe PDS Data</button>
        </form>
    </div>
  </main>

    <script>
        async function runAction(url, method = 'GET') {
            const resDiv = document.getElementById('action-result');
            resDiv.style.display = 'block';
            resDiv.style.background = '#f8fafc';
            resDiv.innerText = 'Running...';
            
            let headers = {};
            let body = undefined;

            if (method === 'POST') {
                const password = prompt("Enter PDS password for authentication:");
                if (!password) {
                    resDiv.style.background = '#f8d7da';
                    resDiv.innerText = 'Password required for POST actions';
                    return;
                }
                try {
                    // Quick login to get a token for the action
                    const loginRes = await fetch('/xrpc/com.atproto.server.createSession', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ identifier: '${user.did}', password })
                    });
                    const loginData = await loginRes.json();
                    if (!loginRes.ok) throw new Error(loginData.message || 'Login failed');
                    headers['Authorization'] = 'Bearer ' + loginData.accessJwt;
                } catch (e) {
                    resDiv.style.background = '#fff5f5';
                    resDiv.innerText = 'Auth Error: ' + e.message;
                    return;
                }
            }

            try {
                const res = await fetch(url, { method, headers, body });
                const data = await res.json();
                resDiv.style.background = res.ok ? '#f0fdf4' : '#fff5f5';
                resDiv.innerText = JSON.stringify(data, null, 2);
            } catch (e) {
                resDiv.style.background = '#fff5f5';
                resDiv.innerText = 'Error: ' + e.message;
            }
        }

        document.getElementById('register-fedcm')?.addEventListener('click', async () => {
            const status = document.getElementById('fedcm-status');
            status.textContent = 'Registering...';

            if (!window.IdentityProvider || typeof IdentityProvider.register !== 'function') {
                status.textContent = 'IdentityProvider.register is unavailable in this browser.';
                return;
            }

            try {
                const result = await IdentityProvider.register(${JSON.stringify(configUrl)});
                status.textContent = 'IdentityProvider.register(configUrl) returned: ' + result;
            } catch (err) {
                status.textContent = 'IdentityProvider.register failed: ' + err.message;
            }
        });

        document.getElementById('unregister-fedcm')?.addEventListener('click', async () => {
            const status = document.getElementById('fedcm-status');
            status.textContent = 'Unregistering...';

            if (!window.IdentityProvider || typeof IdentityProvider.unregister !== 'function') {
                status.textContent = 'IdentityProvider.unregister is unavailable in this browser.';
                return;
            }

            try {
                const result = await IdentityProvider.unregister(${JSON.stringify(configUrl)});
                status.textContent = 'IdentityProvider.unregister(configUrl) returned: ' + result;
            } catch (err) {
                status.textContent = 'IdentityProvider.unregister failed: ' + err.message;
            }
        });
    </script>
</body>
</html>
  `;
  res.send(html);
});
router.post('/debug/reset', requireBrowserSession, async (req, res) => {
  const { password } = req.body;
  const user = req.user;

  if (!password || !user || !verifyPassword(password, user.password)) {
        return res.status(403).send('<h1>Forbidden</h1><p>Incorrect password.</p><a href="/">Back to Dashboard</a>');
    }

    console.log('Wiping ALL PDS data via Web UI...');
    // Don't interleave the wipe with in-flight repo writes.
    const release = await acquireRepoWriteLock();
    try {
      await destroy();
      
      // Re-initialize an empty repo so the PDS remains in a valid state
      await setUpRepo();
    } finally {
      release();
    }
    
    res.send('<h1>Success</h1><p>PDS has been wiped clean and re-initialized.</p><a href="/">Back to Dashboard</a>');
});

export default router;
