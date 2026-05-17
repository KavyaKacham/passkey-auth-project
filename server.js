import express from 'express';
import session from 'express-session';
import { randomUUID } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import {
  initDatabase,
  createUser,
  getUserByUsername,
  getUserById,
  savePasskey,
  getPasskeysByUserId,
  getPasskeyById,
  updatePasskeyCounter,
  deletePasskey,
  getPasskeyCountForUser,
  saveChallenge,
  getChallenge,
  deleteChallenge,
  saveAnonymousChallenge,
  getAnonymousChallenge,
  deleteAnonymousChallenge,
  createSession as createDbSession,
  getActiveSessions,
  deactivateSession,
  deactivateAllUserSessions,
  touchSession,
  getSessionById,
} from './database.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ─── RP Configuration ───────────────────────────────────────────────────────
const rpName = 'PassKey Vault';

const rpID = process.env.VERCEL_URL
  ? process.env.VERCEL_URL.replace('https://', '').replace('http://', '')
  : 'localhost';

const origin = process.env.VERCEL_URL
  ? `https://${process.env.VERCEL_URL}`
  : `http://localhost:${PORT}`;

// ─── Middleware ──────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'passkey-vault-super-secret-key-' + randomUUID(),
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: false, // set to true in production with HTTPS
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);

// Rate limiting (simple in-memory)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 20; // max requests per window

function rateLimit(req, res, next) {
  const key = req.ip + ':' + req.path;
  const now = Date.now();
  const entry = rateLimitMap.get(key);

  if (!entry || now - entry.start > RATE_LIMIT_WINDOW) {
    rateLimitMap.set(key, { start: now, count: 1 });
    return next();
  }

  entry.count++;
  if (entry.count > RATE_LIMIT_MAX) {
    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }
  next();
}

app.use('/api/', rateLimit);

// ─── Auth Middleware ────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId || !req.session.dbSessionId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  // Verify the DB session is still active (concurrent login check)
  const dbSession = getSessionById(req.session.dbSessionId);
  if (!dbSession || !dbSession.is_active) {
    req.session.destroy(() => { });
    return res.status(401).json({
      error: 'Session invalidated. You may have been logged out because another session was started.',
      code: 'SESSION_INVALIDATED'
    });
  }
  touchSession(req.session.dbSessionId);
  next();
}

// ═══════════════════════════════════════════════════════════════════════════
// REGISTRATION FLOW
// ═══════════════════════════════════════════════════════════════════════════

// Step 1: Generate registration options
app.post('/api/register/options', async (req, res) => {
  try {
    const { username, displayName } = req.body;

    if (!username || username.trim().length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }

    if (username.trim().length > 64) {
      return res.status(400).json({ error: 'Username must be at most 64 characters' });
    }

    if (!/^[a-zA-Z0-9_.-]+$/.test(username.trim())) {
      return res.status(400).json({ error: 'Username can only contain letters, numbers, dots, dashes, and underscores' });
    }

    // Check if username already exists
    const existingUser = getUserByUsername(username);
    if (existingUser) {
      return res.status(409).json({ error: 'Username already taken. Please choose another.' });
    }

    // Create the user first
    const user = createUser(username, displayName || username);

    // Get existing passkeys (will be empty for new user)
    const userPasskeys = getPasskeysByUserId(user.id);

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userName: user.username,
      userDisplayName: user.displayName || user.username,
      attestationType: 'none',
      excludeCredentials: userPasskeys.map(pk => ({
        id: pk.id,
        transports: pk.transports,
      })),
      authenticatorSelection: {
        residentKey: 'required',        // Create discoverable credential (passkey)
        userVerification: 'required',   // Require biometric/PIN verification
      },
      supportedAlgorithmIDs: [-7, -257], // ES256 and RS256 (skip Ed25519 for compatibility)
    });

    // Store challenge for verification
    saveChallenge(user.id, options.challenge, 'registration', options);

    // Remember the user ID in the session for the verification step
    req.session.pendingUserId = user.id;

    res.json(options);
  } catch (error) {
    console.error('Registration options error:', error);
    res.status(500).json({ error: 'Failed to generate registration options' });
  }
});

// Step 2: Verify registration response
app.post('/api/register/verify', async (req, res) => {
  try {
    const userId = req.session.pendingUserId;
    if (!userId) {
      return res.status(400).json({ error: 'No pending registration. Please start over.' });
    }

    const user = getUserById(userId);
    if (!user) {
      return res.status(400).json({ error: 'User not found. Please start over.' });
    }

    const challengeData = getChallenge(userId);
    if (!challengeData || challengeData.type !== 'registration') {
      return res.status(400).json({ error: 'No pending registration challenge. Please start over.' });
    }

    const expectedChallenge = challengeData.options_json.challenge;

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
      });
    } catch (error) {
      console.error('Verification error:', error);
      return res.status(400).json({ error: error.message });
    }

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      const { credential, credentialDeviceType, credentialBackedUp } = registrationInfo;

      // Save the passkey
      savePasskey({
        id: credential.id,
        userId: user.id,
        webAuthnUserID: challengeData.options_json.user.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        transports: credential.transports,
      });

      // Clean up
      deleteChallenge(userId);
      delete req.session.pendingUserId;

      // Auto-login after registration
      // Deactivate any existing sessions first (concurrent login protection)
      deactivateAllUserSessions(user.id);

      const dbSessionId = createDbSession(
        user.id,
        req.ip,
        req.headers['user-agent']
      );
      req.session.userId = user.id;
      req.session.dbSessionId = dbSessionId;

      res.json({ verified: true, username: user.username });
    } else {
      res.status(400).json({ verified: false, error: 'Registration verification failed' });
    }
  } catch (error) {
    console.error('Registration verify error:', error);
    res.status(500).json({ error: 'Failed to verify registration' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// AUTHENTICATION FLOW
// ═══════════════════════════════════════════════════════════════════════════

// Step 1: Generate authentication options (with username)
app.post('/api/login/options', async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const user = getUserByUsername(username);
    if (!user) {
      return res.status(404).json({ error: 'User not found. Please register first.' });
    }

    const userPasskeys = getPasskeysByUserId(user.id);
    if (userPasskeys.length === 0) {
      return res.status(400).json({ error: 'No passkeys registered for this user.' });
    }

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: userPasskeys.map(pk => ({
        id: pk.id,
        transports: pk.transports,
      })),
      userVerification: 'required',
    });

    // Save challenge
    saveChallenge(user.id, options.challenge, 'authentication', options);
    req.session.pendingLoginUserId = user.id;

    res.json(options);
  } catch (error) {
    console.error('Login options error:', error);
    res.status(500).json({ error: 'Failed to generate authentication options' });
  }
});

// Step 1b: Generate authentication options (discoverable / usernameless)
app.get('/api/login/options-discoverable', async (req, res) => {
  try {
    const options = await generateAuthenticationOptions({
      rpID,
      userVerification: 'required',
      // No allowCredentials — browser will show all available passkeys
    });

    // Store with session ID since we don't know the user yet
    saveAnonymousChallenge(req.session.id, options.challenge, options);

    res.json(options);
  } catch (error) {
    console.error('Discoverable login options error:', error);
    res.status(500).json({ error: 'Failed to generate authentication options' });
  }
});

// Step 2: Verify authentication response
app.post('/api/login/verify', async (req, res) => {
  try {
    const body = req.body;
    let user, challengeData, expectedChallenge;

    // Try username-based flow first
    if (req.session.pendingLoginUserId) {
      user = getUserById(req.session.pendingLoginUserId);
      challengeData = getChallenge(user.id);
      if (challengeData) {
        expectedChallenge = challengeData.options_json.challenge;
      }
    }

    // If no username-based challenge, try discoverable (anonymous) flow
    if (!expectedChallenge) {
      const anonChallenge = getAnonymousChallenge(req.session.id);
      if (anonChallenge) {
        expectedChallenge = anonChallenge.options_json.challenge;
        // We need to find the user from the credential
        const passkey = getPasskeyById(body.id);
        if (passkey) {
          user = getUserById(passkey.userId);
        }
        deleteAnonymousChallenge(req.session.id);
      }
    }

    if (!user || !expectedChallenge) {
      return res.status(400).json({ error: 'No pending authentication. Please start over.' });
    }

    // Find the matching passkey
    const passkey = getPasskeyById(body.id);
    if (!passkey) {
      return res.status(400).json({ error: 'Passkey not found.' });
    }

    // Ensure the passkey belongs to the expected user
    if (passkey.userId !== user.id) {
      return res.status(403).json({ error: 'Passkey does not belong to this user.' });
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: {
          id: passkey.id,
          publicKey: passkey.publicKey,
          counter: passkey.counter,
          transports: passkey.transports,
        },
      });
    } catch (error) {
      console.error('Auth verification error:', error);
      return res.status(400).json({ error: error.message });
    }

    const { verified, authenticationInfo } = verification;

    if (verified) {
      // Update counter (clone detection)
      updatePasskeyCounter(passkey.id, authenticationInfo.newCounter);

      // Clean up challenge
      deleteChallenge(user.id);
      delete req.session.pendingLoginUserId;

      // ─── Concurrent Session Edge Case ────────────────────────────
      const activeSessions = getActiveSessions(user.id);

      if (activeSessions.length > 0) {
        // Deactivate all existing sessions (single-session policy)
        deactivateAllUserSessions(user.id);
      }

      // Create a new active session
      const dbSessionId = createDbSession(
        user.id,
        req.ip,
        req.headers['user-agent']
      );
      req.session.userId = user.id;
      req.session.dbSessionId = dbSessionId;

      res.json({
        verified: true,
        username: user.username,
        previousSessionsTerminated: activeSessions.length,
      });
    } else {
      res.status(400).json({ verified: false, error: 'Authentication failed' });
    }
  } catch (error) {
    console.error('Login verify error:', error);
    res.status(500).json({ error: 'Failed to verify authentication' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// PROTECTED ROUTES (require authentication)
// ═══════════════════════════════════════════════════════════════════════════

// Get current user profile
app.get('/api/me', requireAuth, (req, res) => {
  const user = getUserById(req.session.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  const passkeys = getPasskeysByUserId(user.id);
  const activeSessions = getActiveSessions(user.id);

  res.json({
    id: user.id,
    username: user.username,
    displayName: user.display_name,
    createdAt: user.created_at,
    passkeys: passkeys.map(pk => ({
      id: pk.id,
      deviceType: pk.deviceType,
      backedUp: pk.backedUp,
      transports: pk.transports,
      createdAt: pk.createdAt,
    })),
    activeSessions: activeSessions.map(s => ({
      id: s.id,
      ipAddress: s.ip_address,
      userAgent: s.user_agent,
      lastActive: s.last_active,
      isCurrent: s.id === req.session.dbSessionId,
    })),
  });
});

// Add a new passkey to existing account
app.post('/api/passkeys/add/options', requireAuth, async (req, res) => {
  try {
    const user = getUserById(req.session.userId);
    const userPasskeys = getPasskeysByUserId(user.id);

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userName: user.username,
      userDisplayName: user.display_name || user.username,
      attestationType: 'none',
      excludeCredentials: userPasskeys.map(pk => ({
        id: pk.id,
        transports: pk.transports,
      })),
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
      supportedAlgorithmIDs: [-7, -257],
    });

    saveChallenge(user.id, options.challenge, 'registration', options);
    res.json(options);
  } catch (error) {
    console.error('Add passkey options error:', error);
    res.status(500).json({ error: 'Failed to generate options' });
  }
});

app.post('/api/passkeys/add/verify', requireAuth, async (req, res) => {
  try {
    const user = getUserById(req.session.userId);
    const challengeData = getChallenge(user.id);

    if (!challengeData || challengeData.type !== 'registration') {
      return res.status(400).json({ error: 'No pending passkey registration.' });
    }

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge: challengeData.options_json.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
      });
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }

    if (verification.verified && verification.registrationInfo) {
      const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

      savePasskey({
        id: credential.id,
        userId: user.id,
        webAuthnUserID: challengeData.options_json.user.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        transports: credential.transports,
      });

      deleteChallenge(user.id);
      res.json({ verified: true });
    } else {
      res.status(400).json({ verified: false });
    }
  } catch (error) {
    console.error('Add passkey verify error:', error);
    res.status(500).json({ error: 'Failed to verify passkey' });
  }
});

// Remove a passkey
app.delete('/api/passkeys/:credentialId', requireAuth, (req, res) => {
  const userId = req.session.userId;
  const { credentialId } = req.params;

  // Don't allow removing the last passkey
  const count = getPasskeyCountForUser(userId);
  if (count <= 1) {
    return res.status(400).json({
      error: 'Cannot remove your last passkey. Add another passkey first.'
    });
  }

  deletePasskey(credentialId, userId);
  res.json({ success: true });
});

// Terminate a specific session
app.post('/api/sessions/:sessionId/terminate', requireAuth, (req, res) => {
  const { sessionId } = req.params;

  // Don't allow terminating your own current session via this endpoint
  if (sessionId === req.session.dbSessionId) {
    return res.status(400).json({ error: 'Use the logout endpoint to end your current session.' });
  }

  const targetSession = getSessionById(sessionId);
  if (!targetSession || targetSession.user_id !== req.session.userId) {
    return res.status(404).json({ error: 'Session not found.' });
  }

  deactivateSession(sessionId);
  res.json({ success: true });
});

// Terminate all other sessions
app.post('/api/sessions/terminate-others', requireAuth, (req, res) => {
  const userId = req.session.userId;
  const currentDbSessionId = req.session.dbSessionId;

  const activeSessions = getActiveSessions(userId);
  let terminated = 0;
  for (const s of activeSessions) {
    if (s.id !== currentDbSessionId) {
      deactivateSession(s.id);
      terminated++;
    }
  }

  res.json({ success: true, terminatedCount: terminated });
});

// Logout
app.post('/api/logout', (req, res) => {
  if (req.session.dbSessionId) {
    deactivateSession(req.session.dbSessionId);
  }
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to logout' });
    }
    res.json({ success: true });
  });
});

// Check auth status
app.get('/api/auth-status', (req, res) => {
  if (req.session.userId && req.session.dbSessionId) {
    const dbSession = getSessionById(req.session.dbSessionId);
    if (dbSession && dbSession.is_active) {
      const user = getUserById(req.session.userId);
      return res.json({
        authenticated: true,
        username: user?.username,
        displayName: user?.display_name,
      });
    }
  }
  res.json({ authenticated: false });
});

// ─── Start Server ───────────────────────────────────────────────────────────
(async () => {
  await initDatabase();
  console.log('✅ Database initialized');
})();

export default app;
