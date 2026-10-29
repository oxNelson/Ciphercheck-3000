# CipherCheck — Password Security Auditor & Generator

CipherCheck is a privacy-first, client-side password security auditor and generator with an optional account and session foundation.

## Key Features

1. **Local Password Strength Analysis**:
   - 0–100 deterministic rule-based score combining length (0–40), character categories (0–20), character uniqueness (0–15), and pattern resistance (0–25).
   - Five classification bands: Very Weak (0–19), Weak (20–39), Fair (40–64), Strong (65–84), and Very Strong (85–100).
   - Explicit weakness detections: predictable sequential runs, common dictionary and keyboard row patterns, excessive repetition (4+ repeated characters), repeated multi-character sequences, and predictable word+digit constructions.
   - **Private by Design**: Evaluated passwords are never sent over the network or saved.

2. **Secure Password Generator**:
   - Web Crypto API (`crypto.getRandomValues`) with rejection sampling to eliminate modulo bias.
   - Configurable length (1–64) and character categories (uppercase, lowercase, digits, symbols).
   - Guarantee that every selected category is represented in the output.
   - One-click copy with accessible status indicators.

3. **Accessible Light/Dark Mode**:
   - Toggle with sun/moon icons in the header.
   - Defaults to OS `prefers-color-scheme` on first visit.
   - Persists user choice in `localStorage`.
   - Anti-flash inline script prevents theme flicker on page load.

4. **Phase 2 Authentication Foundation**:
   - Server-managed sessions with `HttpOnly`, `SameSite=Lax` cookies.
   - Secure password hashing using native `crypto.scrypt` with random 128-bit salts.
   - IP-based rate limiting (5 attempts/min) to prevent brute-force attacks.
   - PostgreSQL support via `DATABASE_URL` with automatic migration runner.
   - Transparent in-memory fallback if `DATABASE_URL` is not set.
   - Honest handling of unconfigured SMTP services without fake email verification or delivery.

## Running the Application

### Prerequisites
- Node.js 20+ (Node.js 22 recommended)
- npm

### Installation & Development
```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Run automated tests
npm test
```

The application runs at `http://localhost:3000`.

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `PORT` | HTTP port for server | `3000` |
| `NODE_ENV` | Environment mode (`production` enforces `Secure` cookies) | `development` |
| `SMTP_HOST` | SMTP server host for email verification | *(Unset / blocked)* |
| `SMTP_PORT` | SMTP port (e.g., 587) | `587` |
| `SMTP_USER` | SMTP username | *(Unset / blocked)* |
| `SMTP_PASS` | SMTP password | *(Unset / blocked)* |

## Production Deployment Checklist

1. **Environment Variables**:
   - Set `NODE_ENV=production` to ensure session cookies are marked with the `Secure` flag.
   - Set `DATABASE_URL` pointing to your managed PostgreSQL instance (e.g. Neon or Cloud SQL) with `sslmode=require` or `sslmode=verify-full`.
2. **Database Migrations**:
   - Migrations in `lib/db/migrations/0000_initial_users_and_sessions.sql` execute automatically upon server startup when a live PostgreSQL connection is established.
3. **HTTPS / Reverse Proxy**:
   - Deploy behind an SSL-terminating reverse proxy or platform (Cloud Run, Netlify, Render).
   - Ensure the proxy passes `X-Forwarded-Proto: https` so the application recognizes secure connections.
4. **CSRF Protection**:
   - State-changing authentication requests require standard JSON payloads, enforce `Sec-Fetch-Site` restrictions, and validate origin alignment.


## Testing

Run the full automated test suite:
```bash
npm test
```
The test suite validates:
- Analyzer heuristics, score calculations, and weakness detection rules
- Web Crypto generator length and character type enforcement
- Theme toggle DOM attributes and storage persistence
- Auth registration, scrypt hashing, login verification, rate limiting, and session lifecycle