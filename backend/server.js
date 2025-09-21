// --- Authentication Middleware (Bearer JWT preferred, legacy Basic fallback) ---
function parseUsersFile() {
  const users = {};
  try {
    const lines = fs.readFileSync(path.join(__dirname, 'users.txt'), 'utf-8').split('\n');
    for (const line of lines) {
      if (!line.trim() || line.startsWith('#')) continue;
      const [username, password] = line.split(':');
      if (username && password) users[username.trim()] = password.trim();
    }
  } catch (e) {}
  return users;
}

function authMiddleware(req, res, next) {
  const auth = req.headers['authorization'];
  // If no Authorization header, treat as unauthorized (but avoid browser native prompt for assets)
  if (!auth) {
      if (req.path.startsWith('/api')) {
        // Indicate Bearer token auth for API clients
        res.set('WWW-Authenticate', 'Bearer realm="User Visible Realm"');
      }
    return res.status(401).send('Authentication required.');
  }
  // Only accept Bearer JWTs now
  if (!auth.startsWith('Bearer ')) {
    if (req.path.startsWith('/api')) res.set('WWW-Authenticate', 'Bearer realm="User Visible Realm"');
    return res.status(401).send('Authentication required.');
  }
  const token = auth.split(' ')[1];
  const userFromJwt = verifyJwt(token);
  if (userFromJwt) {
    req.user = userFromJwt; // { username, roles }
    return next();
  }
  if (req.path.startsWith('/api')) res.set('WWW-Authenticate', 'Bearer realm="User Visible Realm"');
  return res.status(401).send('Invalid token.');
}

const express = require("express");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const { createClient } = require("redis");
const jwt = require('jsonwebtoken');
const ldap = require('ldapjs');

const app = express();
const cfg = require('./config');
app.use(cors({ origin: cfg.FRONTEND_ORIGIN, credentials: true }));
app.use(express.json());

// cookie helper (minimal)
function parseCookie(req, name) {
  const c = req.headers && req.headers.cookie;
  if (!c) return null;
  const pairs = c.split(/;\s*/);
  for (const p of pairs) {
    const idx = p.indexOf('=');
    if (idx === -1) continue;
    const k = decodeURIComponent(p.slice(0, idx).trim());
    const v = decodeURIComponent(p.slice(idx+1).trim());
    if (k === name) return v;
  }
  return null;
}

function escapeHtml(str) {
  return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// LDAP helper: authenticate a user by binding as that user and return roles (group CNs)
async function ldapAuthenticate(username, password) {
  const base = cfg.LDAP_BASE_DN || 'dc=example,dc=org';
  const peopleOu = cfg.LDAP_PEOPLE_OU || 'ou=people';
  const groupsOu = cfg.LDAP_GROUPS_OU || 'ou=groups';
  const url = cfg.LDAP_URL || 'ldap://localhost:389';
  const userDn = `uid=${username},${peopleOu},${base}`;
  return new Promise((resolve) => {
    const client = ldap.createClient({ url, reconnect: false });
    // attempt to bind as the user to verify password
    client.bind(userDn, password, (err) => {
      if (err) {
        try { client.unbind(()=>{}); } catch (e) {}
        return resolve(null);
      }
      // After successful bind, try to load cached roles from Redis
      (async () => {
        try {
          const cacheKey = `${cfg.LDAP_CACHE_PREFIX}${username}`;
          const cached = await redis.get(cacheKey).catch(()=>null);
          if (cached) {
            try { client.unbind(()=>{}); } catch (e) {}
            const roles = JSON.parse(cached || '[]');
            return resolve({ username, roles });
          }
        } catch (e) { /* ignore cache errors */ }
        // if no cache, search for groups that list this user as a member
        const opts = { filter: `(member=${userDn})`, scope: 'sub', attributes: ['cn'] };
        const groupsBase = `${groupsOu},${base}`;
        const roles = [];
        client.search(groupsBase, opts, (err, res) => {
          if (err) {
            try { client.unbind(()=>{}); } catch (e) {}
            return resolve({ username, roles });
          }
          res.on('searchEntry', (entry) => {
            const obj = entry.object || {};
            const cn = obj.cn;
            if (Array.isArray(cn)) cn.forEach(c => roles.push(String(c)));
            else if (cn) roles.push(String(cn));
          });
          res.on('error', async () => {
            try { client.unbind(()=>{}); } catch (e) {}
            resolve({ username, roles });
          });
          res.on('end', async () => {
            try { client.unbind(()=>{}); } catch (e) {}
            // cache roles in Redis for faster next login
            try {
              const cacheKey = `${cfg.LDAP_CACHE_PREFIX}${username}`;
              await redis.set(cacheKey, JSON.stringify(roles || []), { EX: cfg.LDAP_CACHE_TTL_SECONDS }).catch(()=>{});
            } catch (e) {}
            resolve({ username, roles });
          });
        });
      })();
    });
  });
}


// Redis setup
const redisUrl = cfg.REDIS_URL;
const redis = createClient({
  url: redisUrl,
  socket: {
    reconnectStrategy: (retries) => Math.min(retries * 50, 1000)
  }
});
redis.on('error', (err) => console.error('Redis error', err));
// connect in background, errors are handled by event handler
redis.connect().catch((err) => console.error('Redis connect error', err));

// Listen for Redis key expiration events so we can immediately remove Postgres rows (and cascade comments)
// This uses Redis keyspace notifications; we'll attempt to enable them and subscribe to expired events.
const redisSub = createClient({ url: redisUrl });
redisSub.on('error', (err) => console.error('Redis sub error', err));
(async () => {
  try {
    await redisSub.connect();
    // Try to ensure Redis is configured to emit expired events
    try { await redis.configSet('notify-keyspace-events', 'Ex'); } catch (e) { /* best-effort */ }
    await redisSub.subscribe('__keyevent@0__:expired', async (message) => {
      try {
        if (!message || !message.startsWith(SNAP_PREFIX)) return;
        const id = message.substring(SNAP_PREFIX.length);
        if (pool && poolReady) {
          // delete snap row (cascades comments) and return file name to clean filesystem
          const res = await pool.query('DELETE FROM snaps WHERE id = $1 RETURNING file', [String(id)]).catch(console.error);
          if (res && res.rows) {
            for (const r of res.rows) {
              try { fs.unlinkSync(path.join(cfg.UPLOADS_DIR, r.file)); } catch (e) {}
            }
          }
        }
      } catch (err) {
        console.error('Error handling expired event', err);
      }
    });
    console.log('Subscribed to Redis expired events');
  } catch (err) {
    console.error('Failed to start Redis subscriber for expired events', err);
  }
})();

// Pub/Sub channel for chat messages so multiple backend instances can broadcast
const CHAT_CHANNEL = cfg.CHAT_CHANNEL;
const INSTANCE_ID = require('crypto').randomBytes(8).toString('hex');
const CHAT_STREAM = cfg.CHAT_STREAM;
const LAST_READ_PREFIX = cfg.LAST_READ_PREFIX;
// Subscribe to chat channel to forward messages to local WS clients
(async () => {
  try {
    // subscribe a handler for chat messages
    await redisSub.subscribe(CHAT_CHANNEL, (payload) => {
      try {
        const envelope = JSON.parse(payload || '{}');
        const msg = envelope && envelope.msg ? envelope.msg : null;
        if (!msg) return;
        // Broadcast to local WebSocket clients
        for (const c of wss.clients) {
          if (c.readyState === WebSocket.OPEN) {
            try { c.send(JSON.stringify(msg)); } catch (e) { /* ignore send errors */ }
          }
        }
      } catch (err) {
        console.error('Error handling chat pubsub message', err);
      }
    });
    console.log('Subscribed to Redis chat channel', CHAT_CHANNEL);
  } catch (err) {
    console.error('Failed to subscribe to chat channel', err);
  }
})();

// Helper to broadcast a message to local WS clients
function broadcastToLocal(msg) {
  for (const c of wss.clients) {
    if (c.readyState === WebSocket.OPEN) {
      try { c.send(JSON.stringify(msg)); } catch (e) { /* ignore send errors */ }
    }
  }
}

// On startup, replay any missed messages from the Redis stream if we have a last-read id
async function replayStream() {
  try {
    const lastKey = LAST_READ_PREFIX + INSTANCE_ID;
    let lastId = await redis.get(lastKey);
    if (!lastId) {
      // if we have no last-read id, don't replay history to avoid huge replays; start from '$'
      await redis.set(lastKey, '$');
      lastId = '$';
      console.log('No last-read id for stream; starting at $ (no replay)');
      return;
    }
    if (lastId === '$') {
      console.log('Last-read id is $, nothing to replay');
      return;
    }
    console.log('Replaying chat stream from id', lastId);
    // Read in batches until no more
    while (true) {
      const res = await redis.sendCommand(['XREAD', 'COUNT', '100', 'STREAMS', CHAT_STREAM, lastId]);
      if (!res) break;
      // res format: [[stream, [[id, [key, value, ...]], ...]]]
      for (const streamEntry of res) {
        const entries = streamEntry[1];
        for (const entry of entries) {
          const id = entry[0];
          const keyvals = entry[1];
          // find payload field
          let payload = null;
          for (let i = 0; i < keyvals.length; i += 2) {
            if (keyvals[i] === 'payload') payload = keyvals[i+1];
          }
          if (payload) {
            try {
              const msg = JSON.parse(payload);
              broadcastToLocal(msg);
            } catch (e) { /* ignore parse errors */ }
          }
          lastId = id;
          await redis.set(lastKey, lastId).catch(()=>{});
        }
      }
      // if fewer than 100 entries returned then we're caught up
      if (!res || res.length === 0) break;
      // continue loop to fetch next batch (starting from lastId)
      // advance lastId by using the last seen id
      // increment so next XREAD won't return same id; Redis XREAD expects lastId to be the ID to start from; use lastId as-is to fetch > lastId
    }
    console.log('Replay complete up to', await redis.get(LAST_READ_PREFIX + INSTANCE_ID));
  } catch (err) {
    console.error('Error replaying chat stream', err);
  }
}

// Kick off replay in background
replayStream().catch(err => console.error('Replay failed', err));

// Postgres setup (for persistence)
const { Pool } = require('pg');
const dbUrl = process.env.DATABASE_URL;
let pool;
let poolReady = false;
if (dbUrl) {
  pool = new Pool({ connectionString: dbUrl });
  // initialize tables with retry until Postgres is ready
  (async function initPostgres() {
    const maxAttempts = 30;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        await pool.query('SELECT 1');
        // create tables
        await pool.query(`
          CREATE TABLE IF NOT EXISTS snaps (
            id TEXT PRIMARY KEY,
            sender TEXT,
            recipients TEXT[],
            file TEXT,
            time BIGINT,
            expiresAt BIGINT,
            viewOnce BOOLEAN,
            message TEXT
          )
        `);
        await pool.query(`
          CREATE TABLE IF NOT EXISTS comments (
            id SERIAL PRIMARY KEY,
            snap_id TEXT REFERENCES snaps(id) ON DELETE CASCADE,
            user_name TEXT,
            text TEXT,
            time BIGINT
          )
        `);
        await pool.query(`
          CREATE TABLE IF NOT EXISTS read_marks (
            snap_id TEXT REFERENCES snaps(id) ON DELETE CASCADE,
            user_name TEXT,
            PRIMARY KEY (snap_id, user_name)
          )
        `);
        poolReady = true;
        console.log('Postgres initialized');
        break;
      } catch (err) {
        console.error('Postgres init attempt', attempt, 'failed:', err.message);
        await new Promise(r => setTimeout(r, 1000 * attempt));
      }
    }
    if (!poolReady) console.error('Postgres not ready after retries, continuing without persistence');
  })();
}

// Storage setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, cfg.UPLOADS_DIR + '/'),
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

const SNAP_PREFIX = cfg.SNAP_PREFIX;

// Helper to compute expiresAt (ms) and redis EX seconds and viewOnce flag based on ttl mode
function computeExpiry(ttlMode) {
  // ttlMode: '24h' | 'viewOnce' | 'indefinite' or numeric seconds
  if (!ttlMode) ttlMode = '24h';
  if (ttlMode === '24h') {
    return { expiresAt: Date.now() + 24 * 60 * 60 * 1000, exSeconds: 24 * 60 * 60, viewOnce: false };
  }
  if (ttlMode === 'viewOnce') {
    return { expiresAt: Date.now() + 24 * 60 * 60 * 1000, exSeconds: 24 * 60 * 60, viewOnce: true };
  }
  if (ttlMode === 'indefinite') {
    return { expiresAt: null, exSeconds: null, viewOnce: false };
  }
  // if numeric string provided, treat as seconds
  const n = parseInt(String(ttlMode), 10);
  if (!isNaN(n) && n > 0) {
    return { expiresAt: Date.now() + n * 1000, exSeconds: n, viewOnce: false };
  }
  // fallback
  return { expiresAt: Date.now() + 24 * 60 * 60 * 1000, exSeconds: 24 * 60 * 60, viewOnce: false };
}

// WebSocket-based chat (using ws). We'll attach WS to the HTTP server below.
// For now we accept a query param 'auth' containing base64(username:password) so the WS handshake can be authenticated.
// Messages sent via POST /api/chat are broadcast to connected WS clients.
const WebSocket = require('ws');
const http = require('http');

// Create HTTP server from Express app so we can attach ws
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

// Helper to authenticate token: accepts Bearer JWTs, websocket subprotocol tokens, or legacy base64 username:password
function parseAuthToken(b64) {
  try {
    if (!b64) return null;
    // Accept Bearer <token>
    if (b64.startsWith('Bearer ')) {
      const t = b64.split(' ')[1];
      return verifyJwt(t);
    }
    // handle v1.<base64url> (from Sec-WebSocket-Protocol) or raw JWT
    let token = b64;
    if (token.startsWith('v1.')) token = token.slice(3);
    // If token contains a '.', it's likely a JWT already
    if (token.indexOf('.') !== -1) {
      const possibleJwt = token.replace(/\s+/g, '');
      const verified = verifyJwt(possibleJwt);
      if (verified) return verified; // returns { username, roles }
    }
    return null;
  } catch (e) { return null; }
}

const JWT_SECRET = cfg.JWT_SECRET;
const ACCESS_TTL = cfg.ACCESS_TTL; // short-lived access token
const REFRESH_TTL_SECONDS = cfg.REFRESH_TTL_SECONDS; // seconds

function issueAccessToken(username) {
  const jti = require('crypto').randomBytes(8).toString('hex');
  // allow username to be an object { username, roles } for convenience
  let user = username;
  let roles = [];
  if (typeof username === 'object' && username !== null) {
    user = username.username || username.user || '';
    roles = username.roles || [];
  }
  const token = jwt.sign({ sub: user, jti, roles }, JWT_SECRET, { expiresIn: ACCESS_TTL });
  return { token, jti };
}

async function issueRefreshToken(username) {
  // username may be string or object { username, roles }
  const r = require('crypto').randomBytes(24).toString('hex');
  const payload = typeof username === 'string' ? { username, roles: [] } : username;
  await redis.set(`${cfg.REFRESH_PREFIX}${r}`, JSON.stringify(payload), { EX: REFRESH_TTL_SECONDS }).catch(()=>{});
  return r;
}

async function revokeRefreshToken(rtoken) {
  try { await redis.del(`${cfg.REFRESH_PREFIX}${rtoken}`); } catch(e){}
}

async function revokeJti(jti, expiresAtSeconds) {
  try {
    const ttl = Math.max(1, expiresAtSeconds - Math.floor(Date.now()/1000));
  await redis.set(`${cfg.REVOKED_JTI_PREFIX}${jti}`, '1', { EX: ttl });
  } catch (e) {}
}

async function verifyJwt(token) {
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload) return null;
    const jti = payload.jti;
    if (jti) {
      try {
        const revoked = await redis.get(`${cfg.REVOKED_JTI_PREFIX}${jti}`);
        if (revoked) return null;
      } catch (e) { /* ignore redis errors */ }
    }
    const username = payload.sub || payload.username || null;
    const roles = payload.roles || [];
    return username ? { username, roles } : null;
  } catch (e) {
    return null;
  }
}

// Login endpoint to exchange legacy credentials for a short-lived JWT
app.post('/api/login', express.json(), async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ ok: false, error: 'Missing credentials' });
  // Try LDAP authentication first (if LDAP configured)
  let roles = [];
  let authed = false;
  if (cfg.LDAP_URL) {
    const ldapRes = await ldapAuthenticate(username, password).catch(() => null);
    if (ldapRes) {
      authed = true;
      roles = ldapRes.roles || [];
    }
  }
  // Fallback to local users file if LDAP not configured or failed
  if (!authed) {
    const users = parseUsersFile();
    if (!users[username] || users[username] !== password) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
  }
  // include roles in access token
  const access = issueAccessToken({ username, roles });
  const refresh = await issueRefreshToken({ username, roles });
  // set httpOnly refresh cookie
  const secureFlag = cfg.COOKIE_SECURE ? 'Secure; ' : '';
  res.setHeader('Set-Cookie', `${cfg.COOKIE_NAME}=${encodeURIComponent(refresh)}; HttpOnly; ${secureFlag}Path=/; Max-Age=${REFRESH_TTL_SECONDS}; SameSite=Lax`);
  res.json({ ok: true, accessToken: access.token, expiresIn: ACCESS_TTL, roles });
});

// Exchange refresh token for new access token
app.post('/api/refresh', express.json(), async (req, res) => {
  try {
    // read refresh token from cookie
  const refreshToken = parseCookie(req, cfg.COOKIE_NAME);
    if (!refreshToken) return res.status(400).json({ ok: false, error: 'Missing refresh token' });
  const oldKey = `${cfg.REFRESH_PREFIX}${refreshToken}`;
    // Generate a new refresh token value we will atomically set if the old token exists
    const newRefresh = require('crypto').randomBytes(24).toString('hex');
  const newKey = `${cfg.REFRESH_PREFIX}${newRefresh}`;
    // Lua script: get the username stored at oldKey, if present delete oldKey and set newKey -> username with EX TTL
    const lua = `
      local old = KEYS[1]
      local new = KEYS[2]
      local ttl = tonumber(ARGV[1])
      local username = redis.call('GET', old)
      if not username then return nil end
      redis.call('DEL', old)
      redis.call('SET', new, username, 'EX', ttl)
      return username
    `;
  const execResult = await redis.eval(lua, { keys: [oldKey, newKey], arguments: [String(REFRESH_TTL_SECONDS)] });
    const stored = execResult || null;
  if (!stored) return res.status(401).json({ ok: false, error: 'Invalid refresh token' });
    let parsed = null;
    try { parsed = JSON.parse(stored); } catch (e) { parsed = { username: String(stored), roles: [] }; }
  const username = parsed.username || parsed.user || String(parsed);
  const roles = parsed.roles || [];
  // rotate: issue new access token including roles
  const access = issueAccessToken({ username, roles });
  const secureFlag = cfg.COOKIE_SECURE ? 'Secure; ' : '';
  res.setHeader('Set-Cookie', `${cfg.COOKIE_NAME}=${encodeURIComponent(newRefresh)}; HttpOnly; ${secureFlag}Path=/; Max-Age=${REFRESH_TTL_SECONDS}; SameSite=Lax`);
  res.json({ ok: true, accessToken: access.token, expiresIn: ACCESS_TTL, roles });
  } catch (e) {
    console.error('Refresh failed', e);
    res.status(500).json({ ok: false });
  }
});

// Logout: revoke refresh token and optionally revoke access jti
app.post('/api/logout', express.json(), async (req, res) => {
  try {
    // revoke refresh token from cookie
  const refreshToken = parseCookie(req, cfg.COOKIE_NAME);
  if (refreshToken) await revokeRefreshToken(refreshToken);
  // clear cookie
  res.setHeader('Set-Cookie', `${cfg.COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`);
    // optionally revoke access jti if provided
    const { accessJti, accessExp } = req.body || {};
    if (accessJti && accessExp) await revokeJti(accessJti, accessExp);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false });
  }
});

// Map of connected clients (ws) -> username
const wsClients = new Map();

// handle upgrades
server.on('upgrade', (req, socket, head) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (url.pathname === '/api/chat/ws') {
      // Determine token source first (Authorization header, query param, or Sec-WebSocket-Protocol)
      let token = null;
      let tokenSource = null;
      if (req.headers && req.headers.authorization) { token = req.headers.authorization; tokenSource = 'authorization'; }
      if (!token && url.searchParams.get('auth')) { token = url.searchParams.get('auth'); tokenSource = 'query'; }
      if (!token && req.headers && req.headers['sec-websocket-protocol']) { token = req.headers['sec-websocket-protocol'].split(',')[0]; tokenSource = 'sec-websocket-protocol'; }
      const preview = token ? (token.length > 12 ? token.slice(0,6) + '...' + token.slice(-4) : token) : null;
      console.log('WS token source:', tokenSource, 'preview:', preview);
  const user = parseAuthToken(token);
      if (!user) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }
      wss.handleUpgrade(req, socket, head, (ws) => {
      ws.user = user;
      wsClients.set(ws, user);
  ws.send(JSON.stringify({ system: true, text: `hello ${user.username}` }));
      // After a client connects, send missed messages for this user (per-user replay)
      (async function sendMissedToUser(u, socket) {
        try {
          const lastKey = LAST_READ_PREFIX + String(u.username);
          const lastId = await redis.get(lastKey);
          if (!lastId) {
            // No last-read: send last N messages as a warm-up
            const recent = await redis.xRange(CHAT_STREAM, '-', '+', { COUNT: 100 });
            for (const e of recent) {
              const id = e[0];
              const fields = e[1] || {};
              const payload = fields.payload || null;
              if (payload) {
                try { socket.send(payload); } catch (e) {}
              }
              // update last-read to most recent
              await redis.set(lastKey, id).catch(()=>{});
            }
            return;
          }
          if (lastId === '$') return;
          // read messages after lastId (exclusive)
          const entries = await redis.xRange(CHAT_STREAM, '(' + lastId, '+');
          for (const e of entries) {
            const id = e[0];
            const fields = e[1] || {};
            const payload = fields.payload || null;
            if (payload) {
              try { socket.send(payload); } catch (e) {}
            }
            await redis.set(lastKey, id).catch(()=>{});
          }
        } catch (err) {
          console.error('Failed to send missed messages to user', u, err);
        }
      })(user, ws);
      ws.on('message', async (data) => {
        try {
          const parsed = JSON.parse(data.toString());
          const msg = { id: Date.now() + Math.floor(Math.random()*1000), from: user.username, to: parsed.to || null, text: escapeHtml(parsed.text || ''), time: Date.now() };
          // append to Redis stream for durability
          try {
            await redis.xAdd(CHAT_STREAM, '*', { payload: JSON.stringify(msg) });
          } catch (e) { /* best-effort */ }
          // publish to Redis channel for multi-instance broadcast
          try { redis.publish(CHAT_CHANNEL, JSON.stringify({ instance: INSTANCE_ID, msg })); } catch (e) { /* best-effort */ }
          // persist if possible
          if (pool && poolReady) {
            pool.query('CREATE TABLE IF NOT EXISTS chat_messages (id TEXT PRIMARY KEY, from_user TEXT, to_user TEXT, text TEXT, time BIGINT)').catch(()=>{});
            pool.query('INSERT INTO chat_messages(id, from_user, to_user, text, time) VALUES($1,$2,$3,$4,$5)', [String(msg.id), msg.from, msg.to, msg.text, msg.time]).catch(()=>{});
          }
        } catch (e) {}
      });
      ws.on('close', () => { wsClients.delete(ws); });
    });
    } else {
      console.log('WS upgrade path did not match, rejecting', { pathname: url.pathname });
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
    }
  } catch (err) {
    console.error('Error in upgrade handler', err);
    try { socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n'); } catch(e){}
    try { socket.destroy(); } catch(e){}
  }
});

// POST /api/chat - post a chat message (body: { to, text })
app.post('/api/chat', authMiddleware, express.json(), async (req, res) => {
  const { to, text, ttl } = req.body || {};
  if (!text || !text.trim()) return res.status(400).send('Empty');
  const expiry = computeExpiry(ttl || '24h');
  const msg = { id: Date.now() + Math.floor(Math.random()*1000), from: req.user.username, to: to || null, text: escapeHtml(text.toString()), time: Date.now(), expiresAt: expiry.expiresAt, viewOnce: expiry.viewOnce };
  // broadcast to WS clients
  try {
    await redis.xAdd(CHAT_STREAM, '*', { payload: JSON.stringify(msg) });
  } catch (e) { /* best-effort */ }
  try { await redis.publish(CHAT_CHANNEL, JSON.stringify({ instance: INSTANCE_ID, msg })); } catch (e) { /* best-effort */ }
  // persist
  if (pool && poolReady) {
    try {
      await pool.query('CREATE TABLE IF NOT EXISTS chat_messages (id TEXT PRIMARY KEY, from_user TEXT, to_user TEXT, text TEXT, time BIGINT, expires_at BIGINT, view_once BOOLEAN)');
      await pool.query('INSERT INTO chat_messages(id, from_user, to_user, text, time, expires_at, view_once) VALUES($1,$2,$3,$4,$5,$6,$7)', [String(msg.id), msg.from, msg.to, msg.text, msg.time, msg.expiresAt || null, msg.viewOnce || false]);
    } catch (e) { console.error('Failed to persist chat message', e); }
  }
  res.json({ ok: true, msg });
});


// Shared handlers so we can expose both legacy and /api routes
async function handleUpload(req, res) {
  const { viewOnce } = req.body;
  // recipient may be provided as `to` field (single username) or empty for public
  const to = (req.body.to || req.body.recipient || "").trim();
  const recipients = to ? [to] : [];
  const ttlMode = req.body.ttl || (viewOnce === 'true' ? 'viewOnce' : '24h');
  const expiry = computeExpiry(ttlMode);
  const id = Date.now() + Math.floor(Math.random() * 10000);
  const snap = {
    id,
    sender: (req.user && req.user.username) || 'unknown',
    recipients,
    file: req.file.filename,
    time: Date.now(),
    expiresAt: expiry.expiresAt,
    viewOnce: expiry.viewOnce,
    message: escapeHtml(req.body.message || ''),
    comments: [],
    readBy: []
  };
  // Store snap in Redis with expiration (if provided)
  try {
    if (expiry.exSeconds) await redis.set(SNAP_PREFIX + id, JSON.stringify(snap), { EX: expiry.exSeconds });
    else await redis.set(SNAP_PREFIX + id, JSON.stringify(snap));
  } catch (e) { /* best-effort */ }
  // Persist to Postgres for durability (optional)
  if (pool && poolReady) {
    await pool.query(
      'INSERT INTO snaps(id, sender, recipients, file, time, expiresAt, viewOnce, message) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO NOTHING',
      [String(id), snap.sender, snap.recipients, snap.file, snap.time, snap.expiresAt, snap.viewOnce, snap.message]
    ).catch(console.error);
  }
  res.json(snap);
}

app.post("/snap", authMiddleware, upload.single("snap"), handleUpload);
app.post("/api/snap", authMiddleware, upload.single("snap"), handleUpload);


async function handleGetSnaps(req, res) {
  // Ensure expired snaps are cleaned up before we list snaps so comments don't remain visible
  try { await cleanupExpiredSnaps(); } catch (e) { /* best-effort */ }

  const keys = await redis.keys(SNAP_PREFIX + "*");
  const snaps = (await Promise.all(keys.map(k => redis.get(k)))).map(s => JSON.parse(s));
  const now = Date.now();
  // Remove expired snaps (should be handled by Redis TTL, but double check)
  // Treat snaps with no expiresAt as indefinite (keep them)
  const validSnaps = snaps.filter(s => (s.expiresAt === null || s.expiresAt === undefined) || s.expiresAt > now);
  // Only return snaps visible to this user (public or recipient or sender)
  const visibleSnaps = validSnaps.filter(s => !s.recipients || s.recipients.length === 0 || s.recipients.includes(req.user.username) || s.sender === req.user.username);
  // Remove view-once snaps after fetch
  const viewOnceSnaps = visibleSnaps.filter(s => s.viewOnce);
  const normalSnaps = visibleSnaps.filter(s => !s.viewOnce);
  // Delete view-once snaps from Redis and filesystem
  for (const snap of viewOnceSnaps) {
    await redis.del(SNAP_PREFIX + snap.id);
    try {
      fs.unlinkSync(path.join("uploads", snap.file));
    } catch (e) {}
    // Remove persistent rows as well (only if DB is ready)
    if (pool && poolReady) await pool.query('DELETE FROM snaps WHERE id = $1', [String(snap.id)]).catch(console.error);
  }
  res.json([...normalSnaps, ...viewOnceSnaps]);
}

app.get("/snaps", authMiddleware, handleGetSnaps);
app.get("/api/snaps", authMiddleware, handleGetSnaps);

// Return list of users from users.txt (authenticated)
// Return authenticated user's profile
app.get('/api/me', authMiddleware, (req, res) => {
  try {
    return res.json({ ok: true, username: req.user.username, roles: req.user.roles || [] });
  } catch (e) { return res.status(500).json({ ok: false }); }
});

app.get('/api/users', authMiddleware, (req, res) => {
  const all = Object.keys(parseUsersFile());
  // only admins may list everyone
  const roles = (req.user && req.user.roles) || [];
  if (roles.includes('admins')) return res.json(all);
  // otherwise return other local users excluding self (maintain previous behavior)
  const users = all.filter(u => u !== req.user.username);
  res.json(users);
});

// Mark a snap as read by the current user
app.post('/api/snaps/:id/read', authMiddleware, async (req, res) => {
  const id = req.params.id;
  const key = SNAP_PREFIX + id;
  const raw = await redis.get(key);
  if (!raw) return res.status(404).send('Not found');
  const snap = JSON.parse(raw);
  // Only recipients or sender can mark as read
  if (snap.recipients && snap.recipients.length > 0 && snap.sender !== req.user.username && !snap.recipients.includes(req.user.username)) {
    return res.status(403).send('Forbidden');
  }
  if (!snap.readBy) snap.readBy = [];
  if (!snap.readBy.includes(req.user.username)) snap.readBy.push(req.user.username);
  await redis.set(key, JSON.stringify(snap), { EX: Math.max(1, Math.floor((snap.expiresAt - Date.now())/1000)) });
  if (pool && poolReady) await pool.query('INSERT INTO read_marks(snap_id, user_name) VALUES($1,$2) ON CONFLICT DO NOTHING', [String(id), req.user.username]).catch(console.error);
  res.json({ ok: true });
});

// Add a comment to a snap
app.post('/api/snaps/:id/comment', authMiddleware, express.json(), async (req, res) => {
  const id = req.params.id;
  const { text } = req.body || {};
  if (!text || !text.trim()) return res.status(400).send('Empty comment');
  const key = SNAP_PREFIX + id;
  const raw = await redis.get(key);
  if (!raw) return res.status(404).send('Not found');
  const snap = JSON.parse(raw);
  // Only recipients or sender can comment
  if (snap.recipients && snap.recipients.length > 0 && snap.sender !== req.user.username && !snap.recipients.includes(req.user.username)) {
    return res.status(403).send('Forbidden');
  }
  if (!snap.comments) snap.comments = [];
  const comment = { user: req.user.username, text: escapeHtml(text.toString()), time: Date.now() };
  snap.comments.push(comment);
  await redis.set(key, JSON.stringify(snap), { EX: Math.max(1, Math.floor((snap.expiresAt - Date.now())/1000)) });
  if (pool && poolReady) await pool.query('INSERT INTO comments(snap_id, user_name, text, time) VALUES($1,$2,$3,$4)', [String(id), req.user.username, comment.text, comment.time]).catch(console.error);
  res.json({ ok: true, comment: comment });
});


// Authenticated route for uploaded images. Only sender or recipients can fetch the file.
app.get('/uploads/:file', authMiddleware, async (req, res) => {
  const file = req.params.file;
  // find a snap in Redis that references this file
  try {
    const keys = await redis.keys(SNAP_PREFIX + '*');
    for (const key of keys) {
      const raw = await redis.get(key);
      if (!raw) continue;
      const snap = JSON.parse(raw);
      if (snap.file === file) {
        // check permissions: public or sender or recipient
  if (!snap.recipients || snap.recipients.length === 0 || snap.sender === req.user.username || snap.recipients.includes(req.user.username)) {
          return res.sendFile(path.resolve('uploads', file));
        } else {
          return res.status(403).send('Forbidden');
        }
      }
    }
    return res.status(404).send('Not found');
  } catch (err) {
    console.error('Error serving upload', err);
    return res.status(500).send('Server error');
  }
});

// Cleanup for expired snaps: remove Redis keys, uploaded files, and Postgres rows (so comments cascade).
async function cleanupExpiredSnaps() {
  try {
    const keys = await redis.keys(SNAP_PREFIX + "*");
    const now = Date.now();
    for (const key of keys) {
      const raw = await redis.get(key);
      if (!raw) continue;
      const snap = JSON.parse(raw);
      if (snap.expiresAt <= now) {
        await redis.del(key);
  try { fs.unlinkSync(path.join(cfg.UPLOADS_DIR, snap.file)); } catch (e) {}
      }
    }

    // Also purge Postgres rows for expired snaps so comments are removed promptly
    if (pool && poolReady) {
      try {
        const { rows } = await pool.query('DELETE FROM snaps WHERE expiresAt <= $1 RETURNING id, file', [now]);
        for (const r of rows) {
          try { fs.unlinkSync(path.join(cfg.UPLOADS_DIR, r.file)); } catch (e) {}
          try { await redis.del(SNAP_PREFIX + r.id); } catch (e) {}
        }
      } catch (err) {
        console.error('Error cleaning expired snaps from Postgres', err);
      }
      // Reconcile: if Postgres has snaps that Redis no longer holds (missing Redis key), remove them
      try {
        const pgRows = (await pool.query('SELECT id, file, expiresAt FROM snaps')).rows;
        for (const r of pgRows) {
          // skip those already expired (handled above)
          if (r.expiresat <= now) continue;
          const exists = await redis.exists(SNAP_PREFIX + r.id);
          if (!exists) {
            // remove stale Postgres row so comments don't remain
            await pool.query('DELETE FROM snaps WHERE id = $1', [r.id]).catch(console.error);
            try { fs.unlinkSync(path.join(cfg.UPLOADS_DIR, r.file)); } catch (e) {}
          }
        }
      } catch (err) {
        console.error('Error reconciling Postgres and Redis', err);
      }
    }
  } catch (err) {
    console.error('Error during cleanupExpiredSnaps', err);
  }
}

// Run cleanup right away on startup and then every minute to minimize window where expired comments remain
cleanupExpiredSnaps().catch(err => console.error('Initial cleanup failed', err));
setInterval(cleanupExpiredSnaps, 60 * 1000); // every minute

// Admin endpoint to trigger cleanup manually (protected by authMiddleware)
// Simple RBAC helper
function requireRole(role) {
  return (req, res, next) => {
    try {
      const roles = (req.user && req.user.roles) || [];
      if (roles.includes(role)) return next();
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    } catch (e) { return res.status(403).json({ ok: false, error: 'Forbidden' }); }
  };
}

app.post('/admin/cleanup', authMiddleware, requireRole('admins'), async (req, res) => {
  try {
    await cleanupExpiredSnaps();
    return res.json({ ok: true });
  } catch (err) {
    console.error('Admin cleanup failed', err);
    return res.status(500).json({ ok: false });
  }
});

// Admin: show how many snaps are currently pending in each user's queue
app.get('/admin/snaps-counts', authMiddleware, requireRole('admins'), async (req, res) => {
  try {
    const allUsers = Object.keys(parseUsersFile());
    const counts = {};
    for (const u of allUsers) counts[u] = 0;
    counts._public = 0;
    let total = 0;
    const keys = await redis.keys(SNAP_PREFIX + '*');
    for (const k of keys) {
      const raw = await redis.get(k).catch(()=>null);
      if (!raw) continue;
      let snap = null;
      try { snap = JSON.parse(raw); } catch (e) { continue; }
      total++;
      const isPublic = !snap.recipients || snap.recipients.length === 0;
      if (isPublic) counts._public++;
      for (const u of allUsers) {
        // visible if public, addressed to user, or sent by user
        const visible = isPublic || (snap.recipients && snap.recipients.includes(u)) || snap.sender === u;
        if (!visible) continue;
        // only count if user hasn't read it
        const readBy = snap.readBy || [];
        if (!readBy.includes(u)) counts[u] = (counts[u] || 0) + 1;
      }
    }
    return res.json({ ok: true, counts, total });
  } catch (err) {
    console.error('Failed to compute snaps counts', err);
    return res.status(500).json({ ok: false });
  }
});

// Return recent chat history from Redis stream. Stores per-user last-read id so clients can request deltas later.
app.get('/api/chat/history', authMiddleware, async (req, res) => {
  try {
    const count = Math.min(200, parseInt(req.query.count || '50', 10));
    // XRANGE from - to + returns oldest->newest
    const entries = await redis.xRange(CHAT_STREAM, '-', '+', { COUNT: count });
    // entries is an array of [id, { payload: '...' }]
    const msgs = [];
    let lastId = null;
    for (const e of entries) {
      const id = e[0];
      const fields = e[1] || {};
      const payload = fields.payload || fields.PAYLOAD || null;
      if (!payload) { lastId = id; continue; }
      try {
        const msg = JSON.parse(payload);
        // Skip expired messages
        if (msg.expiresAt && msg.expiresAt <= Date.now()) { lastId = id; continue; }
        // Handle view-once chat messages: if this message is viewOnce and addressed to a specific user,
        // only deliver once to that recipient. Track delivery via Redis key.
        if (msg.viewOnce) {
          const deliveredKey = cfg.CHAT_DELIVERED_PREFIX + String(msg.id) + ':' + String(req.user.username);
          const already = await redis.get(deliveredKey).catch(()=>null);
          if (already) { lastId = id; continue; }
          // if message targets a user, only that user can receive it; if public (to == null), allow anyone once
          if (msg.to && msg.to !== req.user.username) { lastId = id; continue; }
          // mark delivered with TTL matching message expiry (if provided)
          try {
            const ttl = msg.expiresAt ? Math.max(1, Math.floor((msg.expiresAt - Date.now())/1000)) : cfg.LDAP_CACHE_TTL_SECONDS;
            await redis.set(deliveredKey, '1', { EX: ttl }).catch(()=>{});
          } catch (e) {}
          msgs.push(msg);
        } else {
          msgs.push(msg);
        }
      } catch (e) {}
      lastId = id;
    }
    // store last-read id for this user so future reconnects can request >lastId
  if (lastId) await redis.set(cfg.LAST_READ_PREFIX + String(req.user.username), lastId).catch(()=>{});
    res.json({ ok: true, msgs, lastId });
  } catch (err) {
    console.error('Failed to fetch chat history', err);
    res.status(500).json({ ok: false });
  }
});

server.listen(cfg.PORT, () => console.log(`Backend running on port ${cfg.PORT}`));
