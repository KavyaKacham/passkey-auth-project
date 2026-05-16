# SentinelAuth - Passkey Authentication System

SentinelAuth is a modern passwordless authentication system built using WebAuthn and Passkey technology. The project replaces traditional passwords with secure biometric-based authentication such as fingerprint, Face ID, or device PIN.

## Features

- Passwordless authentication using Passkeys
- WebAuthn and FIDO2 based security
- Secure session management
- Phishing-resistant authentication
- Add and manage multiple passkeys
- Active session monitoring
- Responsive cybersecurity-themed dashboard UI

---

## Technologies Used

### Frontend
- HTML
- CSS
- JavaScript

### Backend
- Node.js
- Express.js
- SimpleWebAuthn

### Database
- SQLite

---

## Security Features

- Public-private key cryptography
- Challenge-response authentication
- Secure session handling
- Sign count verification
- Replay attack prevention
- Phishing-resistant domain validation

---

## Project Structure

```bash
project/
│
├── public/
│   ├── index.html
│   ├── styles.css
│   └── app.js
│
├── server.js
├── database.js
├── passkey_auth.db
├── package.json
└── README.md
