import initSqlJs from 'sql.js';
import { randomUUID } from 'crypto';

let db;

export async function initDatabase() {
  const SQL = await initSqlJs();
  db = new SQL.Database();
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT,
      created_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS credentials (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      webauthn_user_id TEXT,
      public_key TEXT NOT NULL,
      counter INTEGER DEFAULT 0,
      device_type TEXT,
      backed_up INTEGER DEFAULT 0,
      transports TEXT,
      created_at INTEGER,
      last_used_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS challenges (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      session_id TEXT,
      challenge TEXT NOT NULL,
      type TEXT,
      options_json TEXT,
      created_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      is_active INTEGER DEFAULT 1,
      ip_address TEXT,
      user_agent TEXT,
      last_active INTEGER,
      created_at INTEGER
    );
  `);
  return db;
}

function run(sql, params = []) {
  db.run(sql, params);
}

function get(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

function all(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

export function createUser(username, displayName) {
  const id = randomUUID();
  run(`INSERT INTO users (id, username, display_name, created_at) VALUES (?, ?, ?, ?)`,
    [id, username, displayName || username, Date.now()]);
  return getUserById(id);
}

export function getUserByUsername(username) {
  return get(`SELECT * FROM users WHERE username = ?`, [username]);
}

export function getUserById(id) {
  return get(`SELECT * FROM users WHERE id = ?`, [id]);
}

export function savePasskey({ id, userId, webAuthnUserID, publicKey, counter, deviceType, backedUp, transports }) {
  run(`INSERT INTO credentials (id, user_id, webauthn_user_id, public_key, counter, device_type, backed_up, transports, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, userId, webAuthnUserID, Buffer.from(publicKey).toString('base64'),
      counter, deviceType, backedUp ? 1 : 0, JSON.stringify(transports || []), Date.now()]);
}

export function getPasskeysByUserId(userId) {
  const rows = all(`SELECT * FROM credentials WHERE user_id = ?`, [userId]);
  return rows.map(pk => ({
    ...pk,
    publicKey: Buffer.from(pk.public_key, 'base64'),
    transports: JSON.parse(pk.transports || '[]'),
    backedUp: pk.backed_up === 1,
    deviceType: pk.device_type,
    createdAt: pk.created_at,
  }));
}

export function getPasskeyById(id) {
  const pk = get(`SELECT * FROM credentials WHERE id = ?`, [id]);
  if (!pk) return null;
  return {
    ...pk,
    publicKey: Buffer.from(pk.public_key, 'base64'),
    transports: JSON.parse(pk.transports || '[]'),
    backedUp: pk.backed_up === 1,
    deviceType: pk.device_type,
    createdAt: pk.created_at,
  };
}

export function updatePasskeyCounter(id, counter) {
  run(`UPDATE credentials SET counter = ?, last_used_at = ? WHERE id = ?`,
    [counter, Date.now(), id]);
}

export function deletePasskey(id, userId) {
  run(`DELETE FROM credentials WHERE id = ? AND user_id = ?`, [id, userId]);
}

export function getPasskeyCountForUser(userId) {
  const row = get(`SELECT COUNT(*) as count FROM credentials WHERE user_id = ?`, [userId]);
  return row ? Number(row.count) : 0;
}

export function saveChallenge(userId, challenge, type, options) {
  run(`DELETE FROM challenges WHERE user_id = ?`, [userId]);
  run(`INSERT INTO challenges (id, user_id, challenge, type, options_json, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
    [randomUUID(), userId, challenge, type, JSON.stringify(options), Date.now()]);
}

export function getChallenge(userId) {
  const row = get(`SELECT * FROM challenges WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`, [userId]);
  if (!row) return null;
  return { ...row, options_json: JSON.parse(row.options_json) };
}

export function deleteChallenge(userId) {
  run(`DELETE FROM challenges WHERE user_id = ?`, [userId]);
}

export function saveAnonymousChallenge(sessionId, challenge, options) {
  run(`INSERT INTO challenges (id, session_id, challenge, type, options_json, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
    [randomUUID(), sessionId, challenge, 'authentication', JSON.stringify(options), Date.now()]);
}

export function getAnonymousChallenge(sessionId) {
  const row = get(`SELECT * FROM challenges WHERE session_id = ? ORDER BY created_at DESC LIMIT 1`, [sessionId]);
  if (!row) return null;
  return { ...row, options_json: JSON.parse(row.options_json) };
}

export function deleteAnonymousChallenge(sessionId) {
  run(`DELETE FROM challenges WHERE session_id = ?`, [sessionId]);
}

export function createSession(userId, ipAddress, userAgent) {
  const id = randomUUID();
  run(`INSERT INTO sessions (id, user_id, is_active, ip_address, user_agent, last_active, created_at) VALUES (?, ?, 1, ?, ?, ?, ?)`,
    [id, userId, ipAddress, userAgent, Date.now(), Date.now()]);
  return id;
}

export function getActiveSessions(userId) {
  return all(`SELECT * FROM sessions WHERE user_id = ? AND is_active = 1`, [userId]);
}

export function deactivateSession(sessionId) {
  run(`UPDATE sessions SET is_active = 0 WHERE id = ?`, [sessionId]);
}

export function deactivateAllUserSessions(userId) {
  run(`UPDATE sessions SET is_active = 0 WHERE user_id = ?`, [userId]);
}

export function touchSession(sessionId) {
  run(`UPDATE sessions SET last_active = ? WHERE id = ?`, [Date.now(), sessionId]);
}

export function getSessionById(sessionId) {
  return get(`SELECT * FROM sessions WHERE id = ?`, [sessionId]);
}