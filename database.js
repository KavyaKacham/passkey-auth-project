import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';
import { randomUUID } from 'crypto';

let db;

export async function initDatabase() {
  if (getApps().length === 0) {
    const serviceAccount = JSON.parse(
      Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8')
    );
    initializeApp({
      credential: cert(serviceAccount),
      databaseURL: process.env.FIREBASE_DATABASE_URL,
    });
  }
  db = getDatabase();
  return db;
}

function ref(path) {
  return db.ref(path);
}

// ─── Users ───────────────────────────────────────────────────────────────────

export async function createUser(username, displayName) {
  const id = randomUUID();
  const user = { id, username, display_name: displayName || username, created_at: Date.now() };
  await ref(`users/${id}`).set(user);
  await ref(`usernames/${username}`).set(id);
  return user;
}

export async function getUserByUsername(username) {
  const snap = await ref(`usernames/${username}`).get();
  if (!snap.exists()) return null;
  const id = snap.val();
  return getUserById(id);
}

export async function getUserById(id) {
  const snap = await ref(`users/${id}`).get();
  return snap.exists() ? snap.val() : null;
}

// ─── Passkeys ────────────────────────────────────────────────────────────────

export async function savePasskey({ id, userId, webAuthnUserID, publicKey, counter, deviceType, backedUp, transports }) {
  const passkey = {
    id,
    user_id: userId,
    webauthn_user_id: webAuthnUserID,
    public_key: Buffer.from(publicKey).toString('base64'),
    counter,
    device_type: deviceType,
    backed_up: backedUp ? 1 : 0,
    transports: JSON.stringify(transports || []),
    created_at: Date.now(),
    last_used_at: Date.now(),
  };
  await ref(`credentials/${id}`).set(passkey);
  await ref(`user_credentials/${userId}/${id}`).set(true);
}

export async function getPasskeysByUserId(userId) {
  const snap = await ref(`user_credentials/${userId}`).get();
  if (!snap.exists()) return [];
  const ids = Object.keys(snap.val());
  const passkeys = await Promise.all(ids.map(id => ref(`credentials/${id}`).get()));
  return passkeys
    .filter(s => s.exists())
    .map(s => formatPasskey(s.val()));
}

export async function getPasskeyById(id) {
  const snap = await ref(`credentials/${id}`).get();
  if (!snap.exists()) return null;
  return formatPasskey(snap.val());
}

function formatPasskey(pk) {
  return {
    ...pk,
    publicKey: Buffer.from(pk.public_key, 'base64'),
    transports: JSON.parse(pk.transports || '[]'),
    backedUp: pk.backed_up === 1,
    deviceType: pk.device_type,
    createdAt: pk.created_at,
  };
}

export async function updatePasskeyCounter(id, counter) {
  await ref(`credentials/${id}`).update({ counter, last_used_at: Date.now() });
}

export async function deletePasskey(id, userId) {
  await ref(`credentials/${id}`).remove();
  await ref(`user_credentials/${userId}/${id}`).remove();
}

export async function getPasskeyCountForUser(userId) {
  const snap = await ref(`user_credentials/${userId}`).get();
  if (!snap.exists()) return 0;
  return Object.keys(snap.val()).length;
}

// ─── Challenges ──────────────────────────────────────────────────────────────

export async function saveChallenge(userId, challenge, type, options) {
  await ref(`challenges/user_${userId}`).set({
    id: randomUUID(),
    user_id: userId,
    challenge,
    type,
    options_json: JSON.stringify(options),
    created_at: Date.now(),
  });
}

export async function getChallenge(userId) {
  const snap = await ref(`challenges/user_${userId}`).get();
  if (!snap.exists()) return null;
  const row = snap.val();
  return { ...row, options_json: JSON.parse(row.options_json) };
}

export async function deleteChallenge(userId) {
  await ref(`challenges/user_${userId}`).remove();
}

export async function saveAnonymousChallenge(sessionId, challenge, options) {
  const safeId = sessionId.replace(/[.#$[\]]/g, '_');
  await ref(`challenges/anon_${safeId}`).set({
    id: randomUUID(),
    session_id: sessionId,
    challenge,
    type: 'authentication',
    options_json: JSON.stringify(options),
    created_at: Date.now(),
  });
}

export async function getAnonymousChallenge(sessionId) {
  const safeId = sessionId.replace(/[.#$[\]]/g, '_');
  const snap = await ref(`challenges/anon_${safeId}`).get();
  if (!snap.exists()) return null;
  const row = snap.val();
  return { ...row, options_json: JSON.parse(row.options_json) };
}

export async function deleteAnonymousChallenge(sessionId) {
  const safeId = sessionId.replace(/[.#$[\]]/g, '_');
  await ref(`challenges/anon_${safeId}`).remove();
}

// ─── Sessions ────────────────────────────────────────────────────────────────

export async function createSession(userId, ipAddress, userAgent) {
  const id = randomUUID();
  const session = {
    id,
    user_id: userId,
    is_active: 1,
    ip_address: ipAddress || '',
    user_agent: userAgent || '',
    last_active: Date.now(),
    created_at: Date.now(),
  };
  await ref(`sessions/${id}`).set(session);
  await ref(`user_sessions/${userId}/${id}`).set(true);
  return id;
}

export async function getSessionById(sessionId) {
  const snap = await ref(`sessions/${sessionId}`).get();
  return snap.exists() ? snap.val() : null;
}

export async function getActiveSessions(userId) {
  const snap = await ref(`user_sessions/${userId}`).get();
  if (!snap.exists()) return [];
  const ids = Object.keys(snap.val());
  const sessions = await Promise.all(ids.map(id => ref(`sessions/${id}`).get()));
  return sessions
    .filter(s => s.exists() && s.val().is_active === 1)
    .map(s => s.val());
}

export async function deactivateSession(sessionId) {
  await ref(`sessions/${sessionId}`).update({ is_active: 0 });
}

export async function deactivateAllUserSessions(userId) {
  const snap = await ref(`user_sessions/${userId}`).get();
  if (!snap.exists()) return;
  const ids = Object.keys(snap.val());
  await Promise.all(ids.map(id => ref(`sessions/${id}`).update({ is_active: 0 })));
}

export async function touchSession(sessionId) {
  await ref(`sessions/${sessionId}`).update({ last_active: Date.now() });
}