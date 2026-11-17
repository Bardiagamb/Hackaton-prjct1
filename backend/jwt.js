const crypto = require('crypto');

function encode(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function hmac(data, key) {
  return crypto.createHmac('sha256', key).update(data).digest('base64url');
}

function sign(payload, key) {
  const header = encode({ alg: 'HS256', typ: 'JWT' });
  const body = encode(payload);
  return `${header}.${body}.${hmac(`${header}.${body}`, key)}`;
}

// returns the payload if the token is good, otherwise null
function verify(token, key) {
  if (typeof token !== 'string') return null;

  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, body, sig] = parts;

  // check the signature first, before trusting anything inside the token
  const expected = Buffer.from(hmac(`${header}.${body}`, key));
  const given = Buffer.from(sig);
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
    return null;
  }

  let head, payload;
  try {
    head = JSON.parse(Buffer.from(header, 'base64url').toString());
    payload = JSON.parse(Buffer.from(body, 'base64url').toString());
  } catch {
    return null;
  }

  // only accept HS256 (blocks "alg": "none" tricks)
  if (head.alg !== 'HS256') return null;
  if (typeof payload.exp !== 'number' || payload.exp < Date.now() / 1000) return null;

  return payload;
}

module.exports = { sign, verify };
