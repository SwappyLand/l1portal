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

## Production deployment checklist

- Set `NODE_ENV=production` and serve the app only behind HTTPS. The production session cookie is Secure and the app trusts one reverse proxy hop.
- Use a unique random `SESSION_SECRET`, protect environment variables, and never commit `.env`.
- Use a PostgreSQL database with TLS where required by the hosting provider, restricted network access, least-privilege credentials, automated backups, and tested restore procedures.
- Restrict inbound traffic to HTTPS at the reverse proxy/firewall. Do not expose PostgreSQL publicly.
- Keep Node.js and dependencies patched. Monitor server logs, database capacity, backup health, and failed login activity.
- In deployment pipelines, install development dependencies for the asset build, run `npm run build`, then deploy `public/` with production dependencies.
- Inter and Font Awesome are copied from the installed npm packages into `public/` during the build and served under the app's origin. The Content Security Policy allows no third-party origins.

The old `admin123` and `viewer123` sample credentials are not migrated. Create a fresh bootstrap administrator and recreate any other accounts with new passwords.
