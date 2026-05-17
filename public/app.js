let startRegistration, startAuthentication, browserSupportsWebAuthn;
document.addEventListener("DOMContentLoaded", () => {
  ({ startRegistration, startAuthentication, browserSupportsWebAuthn } = SimpleWebAuthnBrowser);
});

// ─── Cyber Canvas Background ────────────────────────────────────
(function initCyberCanvas() {
  const c = document.getElementById('cyber-canvas'), ctx = c.getContext('2d');
  let w, h; const particles = []; const PCOUNT = 60;
  function resize() { w = c.width = window.innerWidth; h = c.height = window.innerHeight }
  resize(); window.addEventListener('resize', resize);
  class P {
    constructor() { this.reset() }
    reset() { this.x = Math.random() * w; this.y = Math.random() * h; this.vx = (Math.random() - .5) * .3; this.vy = (Math.random() - .5) * .3; this.r = Math.random() * 2 + .5; this.a = Math.random() * .5 + .1 }
    update() { this.x += this.vx; this.y += this.vy; if (this.x < 0 || this.x > w) this.vx *= -1; if (this.y < 0 || this.y > h) this.vy *= -1 }
    draw() { ctx.beginPath(); ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2); ctx.fillStyle = `rgba(0,255,213,${this.a})`; ctx.fill() }
  }
  for (let i = 0; i < PCOUNT; i++)particles.push(new P());
  function frame() {
    ctx.clearRect(0, 0, w, h);
    particles.forEach(p => { p.update(); p.draw() });
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x, dy = particles[i].y - particles[j].y, d = Math.sqrt(dx * dx + dy * dy);
        if (d < 120) {
          ctx.beginPath(); ctx.moveTo(particles[i].x, particles[i].y); ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(0,255,213,${.08 * (1 - d / 120)})`; ctx.lineWidth = .5; ctx.stroke()
        }
      }
    }
    requestAnimationFrame(frame)
  }
  frame()
})();

// ─── Utilities ──────────────────────────────────────────────────
function showScreen(id) { document.querySelectorAll('.screen').forEach(s => s.classList.remove('active')); document.getElementById(id).classList.add('active') }
function showLoading(t = 'Processing...') { document.getElementById('loading-text').textContent = t; document.getElementById('loading-overlay').classList.remove('hidden') }
function hideLoading() { document.getElementById('loading-overlay').classList.add('hidden') }
function showMessage(t, type = 'error') { const el = document.getElementById('auth-message'); el.textContent = t; el.className = `msg ${type}` }
function hideMessage() { document.getElementById('auth-message').className = 'msg hidden' }
function toast(msg, type = 'info') { const c = document.getElementById('toast-container'), el = document.createElement('div'); el.className = `toast ${type}`; el.textContent = msg; c.appendChild(el); setTimeout(() => { el.classList.add('removing'); setTimeout(() => el.remove(), 300) }, 4000) }

// ─── Tab Switching ──────────────────────────────────────────────
function switchTab(tab) {
  hideMessage();
  document.querySelectorAll('.auth-tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
  if (tab === 'login') { document.getElementById('tab-login').classList.add('active'); document.getElementById('login-form').classList.add('active') }
  else { document.getElementById('tab-register').classList.add('active'); document.getElementById('register-form').classList.add('active') }
}

// ─── Dashboard Sections ─────────────────────────────────────────
function showSection(section) {
  document.querySelectorAll('.dash-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('section-' + section).classList.add('active');
  document.querySelector(`.nav-item[data-section="${section}"]`).classList.add('active');
}

// ─── WebAuthn Check ─────────────────────────────────────────────
if (!browserSupportsWebAuthn()) {
  document.querySelectorAll('.btn-cyber,.btn-ghost').forEach(b => b.disabled = true);
  showMessage('Your browser does not support WebAuthn. Use a modern browser.', 'error');
}

// ─── Registration ───────────────────────────────────────────────
async function handleRegister() {
  hideMessage();
  const username = document.getElementById('reg-username').value.trim();
  const displayName = document.getElementById('reg-displayname').value.trim();
  if (!username || username.length < 3) { showMessage('Username must be at least 3 characters', 'error'); return }
  if (!/^[a-zA-Z0-9_.\-]+$/.test(username)) { showMessage('Username: letters, numbers, . - _ only', 'error'); return }
  try {
    showLoading('Generating passkey options...');
    const optResp = await fetch('/api/register/options', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, displayName: displayName || username }) });
    const optionsJSON = await optResp.json();
    if (!optResp.ok) { hideLoading(); showMessage(optionsJSON.error, 'error'); return }
    const _pendingUserId = optionsJSON._pendingUserId;
    hideLoading(); showLoading('Waiting for passkey creation...');
    let attResp;
    try { attResp = await startRegistration({ optionsJSON }) } catch (e) {
      hideLoading();
      showMessage(e.name === 'InvalidStateError' ? 'Authenticator already registered.' : e.name === 'NotAllowedError' ? 'Passkey creation cancelled.' : 'Error: ' + e.message, e.name === 'NotAllowedError' ? 'warning' : 'error'); return
    }
    showLoading('Verifying credential...');
    const vResp = await fetch('/api/register/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...attResp, _pendingUserId }) });
    const vJSON = await vResp.json(); hideLoading();
    if (vJSON.verified) { toast('Identity created! Welcome to SentinelAuth 🛡️', 'success'); loadDashboard() }
    else showMessage(vJSON.error || 'Registration failed', 'error');
  } catch (err) { hideLoading(); showMessage('Network error. Try again.', 'error'); console.error(err) }
}

// ─── Login ──────────────────────────────────────────────────────
async function handleLogin() {
  hideMessage(); const username = document.getElementById('login-username').value.trim();
  if (!username) { showMessage('Enter your username', 'error'); return }
  try {
    showLoading('Generating challenge...');
    const oR = await fetch('/api/login/options', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username }) });
    const optionsJSON = await oR.json(); if (!oR.ok) { hideLoading(); showMessage(optionsJSON.error, 'error'); return }
    hideLoading(); showLoading('Authenticate with passkey...');
    let asseResp;
    try { asseResp = await startAuthentication({ optionsJSON }) } catch (e) { hideLoading(); showMessage(e.name === 'NotAllowedError' ? 'Authentication cancelled.' : 'Error: ' + e.message, e.name === 'NotAllowedError' ? 'warning' : 'error'); return }
    showLoading('Verifying...');
    const vR = await fetch('/api/login/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(asseResp) });
    const vJ = await vR.json(); hideLoading();
    if (vJ.verified) {
      if (vJ.previousSessionsTerminated > 0) toast(`⚠️ ${vJ.previousSessionsTerminated} previous session(s) terminated`, 'warning');
      toast('Authentication successful 🔓', 'success'); loadDashboard()
    }
    else showMessage(vJ.error || 'Auth failed', 'error');
  } catch (err) { hideLoading(); showMessage('Network error.', 'error'); console.error(err) }
}

// ─── Discoverable Login ─────────────────────────────────────────
async function handleDiscoverableLogin() {
  hideMessage();
  try {
    showLoading('Preparing credential request...');
    const oR = await fetch('/api/login/options-discoverable');
    const optionsJSON = await oR.json(); if (!oR.ok) { hideLoading(); showMessage(optionsJSON.error, 'error'); return }
    hideLoading(); showLoading('Select a passkey...');
    let asseResp;
    try { asseResp = await startAuthentication({ optionsJSON }) } catch (e) { hideLoading(); showMessage(e.name === 'NotAllowedError' ? 'Cancelled.' : 'Error: ' + e.message, e.name === 'NotAllowedError' ? 'warning' : 'error'); return }
    showLoading('Verifying...');
    const vR = await fetch('/api/login/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(asseResp) });
    const vJ = await vR.json(); hideLoading();
    if (vJ.verified) {
      if (vJ.previousSessionsTerminated > 0) toast(`⚠️ ${vJ.previousSessionsTerminated} session(s) terminated`, 'warning');
      toast('Authenticated 🔓', 'success'); loadDashboard()
    }
    else showMessage(vJ.error || 'Auth failed', 'error');
  } catch (err) { hideLoading(); showMessage('Network error.', 'error'); console.error(err) }
}

// ─── Dashboard ──────────────────────────────────────────────────
async function loadDashboard() {
  showScreen('dashboard-screen');
  try {
    const resp = await fetch('/api/me');
    if (!resp.ok) { showScreen('auth-screen'); toast('Session expired', 'error'); return }
    const d = await resp.json();
    // Profile
    document.getElementById('profile-name').textContent = d.username;
    document.getElementById('profile-avatar').textContent = (d.username[0] || 'U').toUpperCase();
    document.getElementById('dash-greeting').textContent = `Welcome, ${d.displayName || d.username}`;
    // Stats
    document.getElementById('ov-passkeys').textContent = d.passkeys.length;
    document.getElementById('ov-sessions').textContent = d.activeSessions.length;
    document.getElementById('ov-created').textContent = new Date(d.createdAt + 'Z').toLocaleDateString();
    const hasMulti = d.passkeys.some(p => p.deviceType === 'multiDevice');
    const hasBacked = d.passkeys.some(p => p.backedUp);
    document.getElementById('ov-status').textContent = d.passkeys.length > 1 && hasMulti ? 'Excellent' : d.passkeys.length >= 1 ? 'Good' : 'At Risk';
    // Render
    renderPasskeys(d.passkeys);
    renderSessions(d.activeSessions);
    renderSecurity(d);
  } catch (err) { console.error(err); toast('Failed to load data', 'error') }
}

function renderPasskeys(passkeys) {
  const c = document.getElementById('passkeys-list');
  if (!passkeys.length) { c.innerHTML = '<div class="empty-state">No passkeys registered yet. Add one above.</div>'; return }
  c.innerHTML = passkeys.map(pk => {
    const tr = (pk.transports || []).join(', ') || 'Unknown';
    const isMulti = pk.deviceType === 'multiDevice';
    const dt = new Date(pk.createdAt + 'Z').toLocaleDateString();
    const icon = tr.includes('internal') ? '💻' : tr.includes('usb') ? '🔑' : tr.includes('hybrid') ? '📱' : '🔐';
    return `<div class="list-item">
      <div class="item-left">
        <div class="item-icon pk">${icon}</div>
        <div class="item-meta">
          <h4>Passkey — ${tr}</h4>
          <p>Registered ${dt} ${pk.backedUp ? '• ☁️ Synced' : ''}</p>
        </div>
        <span class="badge ${isMulti ? 'badge-cyan' : 'badge-purple'}">${isMulti ? 'Multi-Device' : 'Single-Device'}</span>
      </div>
      <button class="btn-sm-danger" onclick="handleRemovePasskey('${pk.id}')">Revoke</button>
    </div>`}).join('');
}

function renderSessions(sessions) {
  const c = document.getElementById('sessions-list');
  if (!sessions.length) { c.innerHTML = '<div class="empty-state">No active sessions.</div>'; return }
  c.innerHTML = sessions.map(s => {
    const la = new Date(s.lastActive + 'Z').toLocaleString();
    const ua = parseUA(s.userAgent);
    return `<div class="list-item">
      <div class="item-left">
        <div class="item-icon sess">${s.isCurrent ? '🟢' : '🔵'}</div>
        <div class="item-meta">
          <h4>${ua} ${s.isCurrent ? '<span class="badge badge-green">Current</span>' : ''}</h4>
          <p>IP: ${s.ipAddress || 'Unknown'} • ${la}</p>
        </div>
      </div>
      ${!s.isCurrent ? `<button class="btn-sm-danger" onclick="handleTerminateSession('${s.id}')">Terminate</button>` : ''}
    </div>`}).join('');
}

function renderSecurity(d) {
  const c = document.getElementById('security-checklist');
  const checks = [
    { label: 'Passkey registered', pass: d.passkeys.length > 0, detail: d.passkeys.length + ' passkey(s)' },
    { label: 'Multi-device passkey', pass: d.passkeys.some(p => p.deviceType === 'multiDevice'), detail: 'Synced across devices' },
    { label: 'Backup available', pass: d.passkeys.some(p => p.backedUp), detail: 'Cloud backup enabled' },
    { label: 'Single active session', pass: d.activeSessions.length <= 1, detail: d.activeSessions.length + ' session(s)' },
    { label: 'Biometric verification', pass: true, detail: 'Required for all auth' },
  ];
  c.innerHTML = checks.map(ch => `<div class="check-item">
    <div class="check-icon ${ch.pass ? 'pass' : 'warn'}">${ch.pass ? '✓' : '!'}</div>
    <span class="check-label">${ch.label}</span>
    <span class="check-status" style="color:${ch.pass ? 'var(--green)' : '#ffaa00'}">${ch.detail}</span>
  </div>`).join('');
}

function parseUA(ua) {
  if (!ua) return 'Unknown';
  if (ua.includes('Edg')) return '🌊 Edge'; if (ua.includes('Chrome')) return '🌐 Chrome';
  if (ua.includes('Firefox')) return '🦊 Firefox'; if (ua.includes('Safari')) return '🧭 Safari';
  return '🌐 Browser';
}

// ─── Passkey Management ─────────────────────────────────────────
async function handleAddPasskey() {
  try {
    showLoading('Generating options...');
    const oR = await fetch('/api/passkeys/add/options', { method: 'POST' });
    const optionsJSON = await oR.json(); if (!oR.ok) { hideLoading(); toast(optionsJSON.error, 'error'); return }
    hideLoading(); showLoading('Register your new passkey...');
    let attResp; try { attResp = await startRegistration({ optionsJSON }) } catch (e) { hideLoading(); toast('Cancelled', 'warning'); return }
    showLoading('Verifying...');
    const vR = await fetch('/api/passkeys/add/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(attResp) });
    const r = await vR.json(); hideLoading();
    if (r.verified) { toast('New passkey registered 🔑', 'success'); loadDashboard() } else toast('Failed', 'error');
  } catch (e) { hideLoading(); toast('Error', 'error'); console.error(e) }
}

async function handleRemovePasskey(id) {
  if (!confirm('Revoke this passkey? You won\'t be able to authenticate with it.')) return;
  try {
    const r = await fetch(`/api/passkeys/${encodeURIComponent(id)}`, { method: 'DELETE' });
    const j = await r.json(); if (r.ok) { toast('Passkey revoked', 'success'); loadDashboard() } else toast(j.error, 'error');
  } catch (e) { toast('Error', 'error') }
}

// ─── Session Management ─────────────────────────────────────────
async function handleTerminateSession(id) {
  try { const r = await fetch(`/api/sessions/${id}/terminate`, { method: 'POST' }); if (r.ok) { toast('Session terminated', 'success'); loadDashboard() } else { const j = await r.json(); toast(j.error, 'error') } } catch (e) { toast('Error', 'error') }
}

async function handleTerminateOtherSessions() {
  try { const r = await fetch('/api/sessions/terminate-others', { method: 'POST' }); const j = await r.json(); if (r.ok) { toast(`${j.terminatedCount} session(s) terminated`, 'success'); loadDashboard() } else toast(j.error, 'error') } catch (e) { toast('Error', 'error') }
}

async function handleLogout() {
  try { await fetch('/api/logout', { method: 'POST' }); toast('Signed out', 'info'); showScreen('auth-screen') } catch (e) { toast('Error', 'error') }
}

// ─── Init ───────────────────────────────────────────────────────
(async () => { try { const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), 5000); const r = await fetch('/api/auth-status', { signal: controller.signal }); clearTimeout(timeout); const d = await r.json(); if (d.authenticated) loadDashboard() } catch (e) { console.log('Auth status check failed, showing login', e); } })();
document.getElementById('login-username').addEventListener('keydown', e => { if (e.key === 'Enter') handleLogin() });
document.getElementById('reg-username').addEventListener('keydown', e => { if (e.key === 'Enter') handleRegister() });