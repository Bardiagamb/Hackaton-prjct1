const http = require('http');
const crypto = require('crypto');
const jwt = require('./jwt');

const PORT = process.env.PORT || 3000;
const USERNAME = 'admin';
const PASSWORD = process.env.ADMIN_PASSWORD || 'BCIT12';
const SECRET = process.env.SECRET || 'defaultSecret';
const JWT_KEY = process.env.JWT_KEY;
const ALLOWED_ORIGINS = (process.env.FRONTEND_ORIGIN || 'http://localhost:5500')
  .split(',')
  .map(s => s.trim());

const TOKEN_SECONDS = 3 * 60 * 60; 

if (!JWT_KEY || JWT_KEY.length < 32) {
  console.error('JWT_KEY is missing or too short (need 32+ chars). Make one with:');
  console.error(`  node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`);
  process.exit(1);
}


const MAX_FAILS_PER_MINUTE = 20;
let fails = 0;
let windowStart = Date.now();

function tooManyFails() {
  if (Date.now() - windowStart > 60 * 1000) {
    fails = 0;
    windowStart = Date.now();
  }
  return fails >= MAX_FAILS_PER_MINUTE;
}

// compare hashes so both sides are the same length and the compare
// takes the same time no matter how many characters match
function sameText(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function getCookie(req, name) {
  const cookies = (req.headers.cookie || '').split(';');
  for (const c of cookies) {
    const i = c.indexOf('=');
    if (i > -1 && c.slice(0, i).trim() === name) return c.slice(i + 1).trim();
  }
  return null;
}

function setTokenCookie(res, token, maxAge) {
  // SameSite=None because the frontend is on a different site.
  // Partitioned so it still works in browsers that block 3rd party cookies.
  res.setHeader('Set-Cookie',
    `token=${token}; HttpOnly; Secure; SameSite=None; Partitioned; Path=/; Max-Age=${maxAge}`);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 1000) {
        reject(new Error('body too big'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('bad json'));
      }
    });
    req.on('error', reject);
  });
}

function send(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

function cors(req, res) {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  res.setHeader('Vary', 'Origin');
}

async function login(req, res) {
  if (tooManyFails()) {
    return send(res, 429, { error: 'Too many failed attempts. Try again in a minute.' });
  }

  let body;
  try {
    body = await readJson(req);
  } catch {
    return send(res, 400, { error: 'Bad request' });
  }
  if (!body || typeof body !== 'object') return send(res, 400, { error: 'Bad request' });

  const userOk = sameText(body.username, USERNAME);
  const passOk = sameText(body.password, PASSWORD);

  if (!userOk || !passOk) {
    fails++;
    return send(res, 401, { error: 'Invalid username or password' });
  }

  const now = Math.floor(Date.now() / 1000);
  const token = jwt.sign({ sub: USERNAME, iat: now, exp: now + TOKEN_SECONDS }, JWT_KEY);
  setTokenCookie(res, token, TOKEN_SECONDS);
  send(res, 200, { ok: true });
}

function me(req, res) {
  const user = jwt.verify(getCookie(req, 'token'), JWT_KEY);
  if (!user) return send(res, 401, { error: 'Not logged in' });

  res.setHeader('Cache-Control', 'no-store');
  send(res, 200, { user: user.sub, secret: SECRET });
}

function logout(req, res) {
  send(res, 200, { ok: true });
}

const server = http.createServer(async (req, res) => {
  cors(req, res);
  res.setHeader('X-Content-Type-Options', 'nosniff');

  const path = req.url.split('?')[0];

  try {
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      return res.end();
    }
    if (req.method === 'GET' && path === '/') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end('prjC1 API is running');
    }
    if (req.method === 'POST' && path === '/api/login') return await login(req, res);
    if (req.method === 'GET' && path === '/api/me') return me(req, res);
    if (req.method === 'POST' && path === '/api/logout') return logout(req, res);

    send(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error(err);
    if (!res.headersSent) send(res, 500, { error: 'Server error' });
  }
});

server.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
  console.log(`Allowed frontend: ${ALLOWED_ORIGINS.join(', ')}`);
  console.log(process.env.ADMIN_PASSWORD ? 'Password: from env' : 'Password: default (BCIT12)');
  console.log(process.env.SECRET ? 'Secret: from env' : 'Secret: default');
});
