/*
 * Mzunguko MVP – Prototype backend (dependency‑free implementation)
 *
 * This server uses only Node.js built‑in modules.  It provides a
 * minimal REST API to support a WhatsApp‑first MVP for the Mzunguko
 * platform.  The goal is to allow local testing without requiring
 * any third‑party packages or an internet connection to install
 * dependencies.  All data is stored in memory.
 *
 * Endpoints:
 *  - GET    /health               → service status
 *  - POST   /register             → create a new trader account
 *  - POST   /login                → authenticate and return a token
 *  - GET    /me                   → return the current user profile
 *  - GET    /wallet               → get wallet balance
 *  - POST   /wallet/add           → add funds to wallet
 *  - POST   /sales                → record a sale
 *  - GET    /sales                → list sales for the logged in user
 *
 * Authentication is handled via tokens issued at login.  Tokens are
 * random opaque strings stored alongside the user ID in memory.
 */

import http from 'http';
import { parse as parseUrl } from 'url';
import { randomUUID, randomBytes, pbkdf2Sync } from 'crypto';

// In‑memory "database".  In production these would be replaced
// with calls to a persistent datastore.
const users = [];
const wallets = [];
const sales = [];
const sessions = {}; // token → { userId, expiresAt }

// Salt length and PBKDF2 parameters for PIN hashing
const SALT_LENGTH = 16;
const ITERATIONS = 10000;
const KEY_LENGTH = 32;
const DIGEST = 'sha256';

/**
 * Hash a numeric PIN using PBKDF2 with a random salt.  Returns
 * an object containing the salt and derived key as hex strings.
 *
 * @param {string} pin The plain text PIN to hash
 */
function hashPin(pin) {
  const salt = randomBytes(SALT_LENGTH);
  const key = pbkdf2Sync(pin, salt, ITERATIONS, KEY_LENGTH, DIGEST);
  return { salt: salt.toString('hex'), hash: key.toString('hex') };
}

/**
 * Verify a plain text PIN against a stored salt/hash pair.
 *
 * @param {string} pin The candidate PIN
 * @param {string} saltHex The salt hex string
 * @param {string} hashHex The expected hash hex string
 */
function verifyPin(pin, saltHex, hashHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const derived = pbkdf2Sync(pin, salt, ITERATIONS, KEY_LENGTH, DIGEST);
  return derived.toString('hex') === hashHex;
}

/**
 * Parse a JSON body from an HTTP request.  Returns a promise
 * resolving to the parsed object or rejecting on errors.
 *
 * @param {http.IncomingMessage} req
 */
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        const parsed = JSON.parse(body);
        resolve(parsed);
      } catch (err) {
        reject(err);
      }
    });
  });
}

/**
 * Send a JSON response with the given status code.
 *
 * @param {http.ServerResponse} res
 * @param {number} status
 * @param {object} payload
 */
function sendJson(res, status, payload) {
  const json = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(json)
  });
  res.end(json);
}

/**
 * Authenticate a request using the Authorization header.  If the
 * token is valid and not expired, returns the user object.  Otherwise
 * returns null.
 *
 * @param {http.IncomingMessage} req
 */
function authenticate(req) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.substring(7);
  const session = sessions[token];
  if (!session || session.expiresAt < Date.now()) {
    return null;
  }
  const user = users.find(u => u.id === session.userId);
  return user || null;
}

/**
 * Create an HTTP server and dispatch requests based on method and
 * pathname.
 */
const server = http.createServer(async (req, res) => {
  const { pathname } = parseUrl(req.url, true);
  // Health check
  if (req.method === 'GET' && pathname === '/health') {
    return sendJson(res, 200, { ok: true, service: 'mzunguko-mvp-prototype' });
  }
  // Register a new trader
  if (req.method === 'POST' && pathname === '/register') {
    try {
      const body = await parseBody(req);
      const {
        phone,
        fullName,
        businessType,
        businessName = '',
        geo = '',
        hours = '',
        pin
      } = body;
      if (!phone || !fullName || !businessType || !pin) {
        return sendJson(res, 400, { error: 'phone, fullName, businessType and pin are required' });
      }
      if (users.some(u => u.phone === phone)) {
        return sendJson(res, 409, { error: 'User with that phone already exists' });
      }
      const { salt, hash } = hashPin(pin.toString());
      const userId = randomUUID();
      const newUser = {
        id: userId,
        phone,
        fullName,
        businessType,
        businessName,
        geo,
        hours,
        role: 'TRADER',
        pinSalt: salt,
        pinHash: hash,
        createdAt: new Date().toISOString()
      };
      users.push(newUser);
      wallets.push({ id: randomUUID(), userId, balance: 0, createdAt: new Date().toISOString() });
      return sendJson(res, 201, { message: 'Registration successful', userId });
    } catch (err) {
      return sendJson(res, 400, { error: 'Invalid JSON body' });
    }
  }
  // Login
  if (req.method === 'POST' && pathname === '/login') {
    try {
      const { phone, pin } = await parseBody(req);
      if (!phone || !pin) {
        return sendJson(res, 400, { error: 'phone and pin are required' });
      }
      const user = users.find(u => u.phone === phone);
      if (!user) {
        return sendJson(res, 401, { error: 'Invalid credentials' });
      }
      const valid = verifyPin(pin.toString(), user.pinSalt, user.pinHash);
      if (!valid) {
        return sendJson(res, 401, { error: 'Invalid credentials' });
      }
      // Create a token and store a session valid for 12 hours
      const token = randomBytes(24).toString('base64url');
      sessions[token] = { userId: user.id, expiresAt: Date.now() + 12 * 60 * 60 * 1000 };
      return sendJson(res, 200, { token });
    } catch (err) {
      return sendJson(res, 400, { error: 'Invalid JSON body' });
    }
  }
  // Protected routes
  const user = authenticate(req);
  if (!user) {
    // If the route is not /health, /register or /login, require auth
    return sendJson(res, 401, { error: 'Unauthorized' });
  }
  // Get current user profile
  if (req.method === 'GET' && pathname === '/me') {
    const { pinSalt, pinHash, ...userInfo } = user;
    return sendJson(res, 200, userInfo);
  }
  // Get wallet balance
  if (req.method === 'GET' && pathname === '/wallet') {
    const wallet = wallets.find(w => w.userId === user.id);
    return sendJson(res, 200, { balance: wallet ? wallet.balance : 0 });
  }
  // Add funds to wallet
  if (req.method === 'POST' && pathname === '/wallet/add') {
    try {
      const { amount } = await parseBody(req);
      const numeric = typeof amount === 'number' ? amount : Number(amount);
      if (!numeric || numeric <= 0) {
        return sendJson(res, 400, { error: 'amount must be a positive number' });
      }
      const wallet = wallets.find(w => w.userId === user.id);
      if (!wallet) {
        return sendJson(res, 404, { error: 'Wallet not found' });
      }
      wallet.balance += numeric;
      return sendJson(res, 200, { message: 'Wallet updated', balance: wallet.balance });
    } catch (err) {
      return sendJson(res, 400, { error: 'Invalid JSON body' });
    }
  }
  // Record a sale
  if (req.method === 'POST' && pathname === '/sales') {
    try {
      const { product, quantity, price, location = '' } = await parseBody(req);
      const qty = typeof quantity === 'number' ? quantity : Number(quantity);
      const pr = typeof price === 'number' ? price : Number(price);
      if (!product || !qty || !pr) {
        return sendJson(res, 400, { error: 'product, quantity and price are required' });
      }
      const total = qty * pr;
      const sale = {
        id: randomUUID(),
        userId: user.id,
        product,
        quantity: qty,
        price: pr,
        total,
        location,
        createdAt: new Date().toISOString()
      };
      sales.push(sale);
      return sendJson(res, 201, { message: 'Sale recorded', sale });
    } catch (err) {
      return sendJson(res, 400, { error: 'Invalid JSON body' });
    }
  }
  // List sales
  if (req.method === 'GET' && pathname === '/sales') {
    const list = sales.filter(s => s.userId === user.id);
    return sendJson(res, 200, list);
  }
  // Unhandled route
  return sendJson(res, 404, { error: 'Not found' });
});

// Start the server on the PORT environment variable or 3000 by default
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Mzunguko MVP (prototype) listening on port ${PORT}`);
});
