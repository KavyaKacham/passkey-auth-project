import initSqlJs from 'sql.js';
import { randomUUID } from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DB_PATH = '/tmp/passkey_auth.db';
let db;

export async function initDatabase() {
  const SQL = await initSqlJs();

  // Load existing DB file if present
  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS passkeys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      webauthn_user_id TEXT NOT NULL,
      public_key BLOB NOT NULL,
      counter INTEGER NOT NULL DEFAULT 0,
      device_type TEXT NOT NULL DEFAULT 'singleDevice',
      backed_up INTEGER NOT NULL DEFAULT 0,
      transports TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      last_active TEXT DEFAULT (datetime('now')),
      is_active INTEGER NOT NULL DEFAULT 1,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS challenges (
      user_id TEXT PRIMARY KEY,
      challenge TEXT NOT NULL,
      type TEXT NOT NULL,
      options_json TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS anonymous_challenges (
      session_id TEXT PRIMARY KEY,
      challenge TEXT NOT NULL,
      options_json TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // Create indexes (IF NOT EXISTS not supported for indexes in all SQLite versions, use try)
  try { db.run('CREATE INDEX idx_passkeys_user ON passkeys(user_id)'); } catch { }
  try { db.run('CREATE INDEX idx_sessions_user ON sessions(user_id)'); } catch { }

  persistDb();
  // Auto-persist every 30 seconds
  //setInterval(persistDb, 30000);
  // Cleanup stale challenges every 5 minutes
  //setInterval(cleanupStaleChallenges, 5 * 60 * 1000);

  return db;
}

function persistDb() {
  try {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  } catch (e) { console.error('DB persist error:', e); }
}

// Helper to get one row as object
function getOne(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  let row = null;
  if (stmt.step()) {
    const cols = stmt.getColumnNames();
    const vals = stmt.get();
    row = {};
    cols.forEach((c, i) => { row[c] = vals[i]; });
  }
  stmt.free();
  return row;
}

// Helper to get all rows
function getAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) {
    const cols = stmt.getColumnNames();
    const vals = stmt.get();
    const row = {};
    cols.forEach((c, i) => { row[c] = vals[i]; });
    rows.push(row);
  }
  stmt.free();
  return rows;
}

// ─── User Operations ────────────────────────────────────────────
export function createUser(username, displayName) {
  const id = randomUUID();
  db.run('INSERT INTO users (id, username, display_name) VALUES (?, ?, ?)',
    [id, username.toLowerCase().trim(), displayName || username]);
  persistDb();
  return { id, username: username.toLowerCase().trim(), displayName: displayName || username };
}

export function getUserByUsername(username) {
  return getOne('SELECT * FROM users WHERE username = ?', [username.toLowerCase().trim()]);
}

export function getUserById(id) {
  return getOne('SELECT * FROM users WHERE id = ?', [id]);
}

// ─── Passkey Operations ─────────────────────────────────────────
export function savePasskey(passkey) {
  // Convert Uint8Array to Buffer for storage
  const pkBuf = passkey.publicKey instanceof Uint8Array
    ? Array.from(passkey.publicKey) : passkey.publicKey;

  db.run(
    `INSERT INTO passkeys (id, user_id, webauthn_user_id, public_key, counter, device_type, backed_up, transports)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [passkey.id, passkey.userId, passkey.webAuthnUserID,
      pkBuf, passkey.counter, passkey.deviceType,
    passkey.backedUp ? 1 : 0,
    passkey.transports ? passkey.transports.join(',') : null]
  );
  persistDb();
}

export function getPasskeysByUserId(userId) {
  const rows = getAll('SELECT * FROM passkeys WHERE user_id = ?', [userId]);
  return rows.map(row => ({
    id: row.id,
    userId: row.user_id,
    webAuthnUserID: row.webauthn_user_id,
    publicKey: new Uint8Array(row.public_key),
    counter: row.counter,
    deviceType: row.device_type,
    backedUp: row.backed_up === 1,
    transports: row.transports ? row.transports.split(',') : undefined,
    createdAt: row.created_at,
  }));
}

export function getPasskeyById(credentialId) {
  const row = getOne('SELECT * FROM passkeys WHERE id = ?', [credentialId]);
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    webAuthnUserID: row.webauthn_user_id,
    publicKey: new Uint8Array(row.public_key),
    counter: row.counter,
    deviceType: row.device_type,
    backedUp: row.backed_up === 1,
    transports: row.transports ? row.transports.split(',') : undefined,
    createdAt: row.created_at,
  };
}

export function updatePasskeyCounter(credentialId, newCounter) {
  db.run('UPDATE passkeys SET counter = ? WHERE id = ?', [newCounter, credentialId]);
  persistDb();
}

export function deletePasskey(credentialId, userId) {
  db.run('DELETE FROM passkeys WHERE id = ? AND user_id = ?', [credentialId, userId]);
  persistDb();
}

export function getPasskeyCountForUser(userId) {
  const row = getOne('SELECT COUNT(*) as count FROM passkeys WHERE user_id = ?', [userId]);
  return row ? row.count : 0;
}

// ─── Challenge Operations ───────────────────────────────────────
export function saveChallenge(userId, challenge, type, optionsJson) {
  // Delete existing first, then insert (sql.js doesn't reliably support INSERT OR REPLACE)
  db.run('DELETE FROM challenges WHERE user_id = ?', [userId]);
  db.run(
    `INSERT INTO challenges (user_id, challenge, type, options_json, created_at)
     VALUES (?, ?, ?, ?, datetime('now'))`,
    [userId, challenge, type, JSON.stringify(optionsJson)]
  );
  persistDb();
}

export function getChallenge(userId) {
  const row = getOne('SELECT * FROM challenges WHERE user_id = ?', [userId]);
  if (!row) return null;
  return { ...row, options_json: JSON.parse(row.options_json) };
}

export function deleteChallenge(userId) {
  db.run('DELETE FROM challenges WHERE user_id = ?', [userId]);
}

export function saveAnonymousChallenge(sessionId, challenge, optionsJson) {
  db.run('DELETE FROM anonymous_challenges WHERE session_id = ?', [sessionId]);
  db.run(
    `INSERT INTO anonymous_challenges (session_id, challenge, options_json, created_at)
     VALUES (?, ?, ?, datetime('now'))`,
    [sessionId, challenge, JSON.stringify(optionsJson)]
  );
}

export function getAnonymousChallenge(sessionId) {
  const row = getOne('SELECT * FROM anonymous_challenges WHERE session_id = ?', [sessionId]);
  if (!row) return null;
  return { ...row, options_json: JSON.parse(row.options_json) };
}

export function deleteAnonymousChallenge(sessionId) {
  db.run('DELETE FROM anonymous_challenges WHERE session_id = ?', [sessionId]);
}

// ─── Session Operations ─────────────────────────────────────────
export function createSession(userId, ipAddress, userAgent) {
  const id = randomUUID();
  db.run('INSERT INTO sessions (id, user_id, ip_address, user_agent) VALUES (?, ?, ?, ?)',
    [id, userId, ipAddress, userAgent]);
  persistDb();
  return id;
}

export function getActiveSessions(userId) {
  return getAll('SELECT * FROM sessions WHERE user_id = ? AND is_active = 1 ORDER BY last_active DESC', [userId]);
}

export function deactivateSession(sessionId) {
  db.run('UPDATE sessions SET is_active = 0 WHERE id = ?', [sessionId]);
  persistDb();
}

export function deactivateAllUserSessions(userId) {
  db.run('UPDATE sessions SET is_active = 0 WHERE user_id = ?', [userId]);
  persistDb();
}

export function touchSession(sessionId) {
  db.run("UPDATE sessions SET last_active = datetime('now') WHERE id = ?", [sessionId]);
}

export function getSessionById(sessionId) {
  return getOne('SELECT * FROM sessions WHERE id = ?', [sessionId]);
}

function cleanupStaleChallenges() {
  db.run("DELETE FROM challenges WHERE created_at < datetime('now', '-5 minutes')");
  db.run("DELETE FROM anonymous_challenges WHERE created_at < datetime('now', '-5 minutes')");
}
