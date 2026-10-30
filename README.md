# L1 Portal

The portal is served by one Node.js application. PostgreSQL is the source of truth for user accounts, login sessions, and portal links. User passwords are stored as Argon2id hashes. The frontend does not store accounts, passwords, or sessions in browser storage.

`portal-data.json` is imported into PostgreSQL as initial link data the first time the backend starts. It is not served directly. Later link additions are written to PostgreSQL. `users.json` is intentionally not used; the old sample accounts must not be used in production.

## Requirements

- Node.js 20 or newer
- PostgreSQL 14 or newer
- HTTPS termination for production (for example, a reverse proxy in front of this single app server)

## Local setup

1. Create a PostgreSQL database and dedicated database user. Give the user access only to this database.
2. Copy `.env.example` to `.env`.
3. Set `DATABASE_URL`, a random `SESSION_SECRET` of at least 32 bytes, and a new `BOOTSTRAP_ADMIN_EMAIL` and unique `BOOTSTRAP_ADMIN_PASSWORD` of at least 12 characters.
4. Install dependencies, build the local Tailwind CSS and vendor assets, and start the application:

   ```powershell
   npm install
   npm run build
   npm start
   ```

5. Open `http://localhost:8000`.

Stop any previously started `python -m http.server` process before starting this app, since both use port 8000 by default.

Generate a session secret with:

```powershell
node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"
```

The first successful startup creates the administrator only if the `users` table is empty, imports the initial links, and creates the PostgreSQL session table. Remove the bootstrap credentials from the server environment after the initial administrator is created. If all admin accounts are later deleted, provision a new one through a controlled database administration procedure rather than restoring a known default password.

## Health, logs, and password management

- `GET /api/health/live` is a liveness probe and does not depend on PostgreSQL.
- `GET /api/health/ready` checks PostgreSQL connectivity and is suitable as the readiness probe.
- The server writes newline-delimited JSON logs to stdout/stderr. Important event names include `http_request`, `auth_login_failed`, `auth_login_succeeded`, `auth_password_changed`, `admin_user_password_reset`, `postgres_pool_error`, and `expired_data_cleanup_failed`.
- Forward logs to a managed logging service. Alert on repeated 5xx responses, database/pool errors, failed cleanup, and unusual authentication failures. Restrict access to logs and set a retention period appropriate for the IP addresses they contain. Passwords are never logged.
- Signed-in users can change their password from the key icon in the sidebar; the current password is required. This revokes all active sessions, including the current one, and requires signing in again with the new password.
- Refreshing the portal tab ends that session and requires the user to sign in again. Switching tabs without refreshing does not end the session.
- An administrator can set a temporary password for another account from User Management. This revokes that account's active sessions. An already-open portal checks session validity every 15 seconds, whenever it returns to the foreground, and on authenticated API failures; it then returns the user to sign-in. Share temporary passwords only through an approved secure channel, and ask the user to change it after signing in. Administrators change their own password through the signed-in user flow, which requires the current password.
- If a user cannot sign in, they must contact an administrator. No email-based recovery or SMTP integration is used.
- Startup removes the unused `password_reset_tokens` table left by the former email recovery feature.

## Tests

`npm test` runs validation tests and the PostgreSQL-backed API integration suite. The API suite is skipped unless `TEST_DATABASE_URL` is configured. Point it at a dedicated, disposable test database that is different from `DATABASE_URL`; the test creates a random schema and drops only that schema when finished. The database role needs permission to create and drop schemas. Never point `TEST_DATABASE_URL` at production.

PowerShell example:

```powershell
$env:TEST_DATABASE_URL = "postgresql://l1portal_test_app:replace-me@localhost:5432/l1portal_test"
npm test
```

The integration flow covers health probes, CSRF, successful and failed login, user creation and role authorization, password changes with the current password, administrator password resets, session revocation, link persistence, and logout.

## Production deployment checklist

- Set `NODE_ENV=production` and serve the app only behind HTTPS. The production session cookie is Secure and the app trusts one reverse proxy hop.
- Use a unique random `SESSION_SECRET`, protect environment variables, and never commit `.env`.
- Establish an identity-verification process for administrator-assisted password resets, and communicate temporary passwords only through an approved secure channel.
- Use a PostgreSQL database with TLS where required by the hosting provider, restricted network access, least-privilege credentials, automated backups, and tested restore procedures.
- Restrict inbound traffic to HTTPS at the reverse proxy/firewall. Do not expose PostgreSQL publicly.
- Keep Node.js and dependencies patched. Monitor server logs, database capacity, backup health, and failed login activity.
- In deployment pipelines, install development dependencies for the asset build, run `npm run build`, then deploy `public/` with production dependencies.
- Inter and Font Awesome are copied from the installed npm packages into `public/` during the build and served under the app's origin. The Content Security Policy allows no third-party origins.

The old `admin123` and `viewer123` sample credentials are not migrated. Create a fresh bootstrap administrator and recreate any other accounts with new passwords.

Administrators can add, edit, and delete portal URLs from the portal interface. These changes are persisted directly in PostgreSQL; viewers can open URLs but cannot modify them.
