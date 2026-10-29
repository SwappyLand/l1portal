require('dotenv').config();

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const argon2 = require('argon2');
const connectPgSimple = require('connect-pg-simple');
const express = require('express');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const helmet = require('helmet');
const { Pool } = require('pg');
const { z } = require('zod');
const { emailSchema, passwordSchema, linkSchema } = require('./lib/validation');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const PgSessionStore = connectPgSimple(session);
const projectDir = __dirname;
const sessionSecret = process.env.SESSION_SECRET;
const isProduction = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT || 8000);

if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL must be configured.');
}

if (!sessionSecret || Buffer.byteLength(sessionSecret) < 32) {
    throw new Error('SESSION_SECRET must contain at least 32 bytes.');
}

if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be a valid TCP port.');
}

if (isProduction) {
    app.set('trust proxy', 1);
}

app.disable('x-powered-by');
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", 'https://cdnjs.cloudflare.com', 'https://fonts.googleapis.com'],
            fontSrc: ["'self'", 'https://cdnjs.cloudflare.com', 'https://fonts.gstatic.com', 'data:'],
            imgSrc: ["'self'", 'data:'],
            connectSrc: ["'self'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            frameAncestors: ["'none'"]
        }
    },
    referrerPolicy: { policy: 'no-referrer' }
}));
app.use(express.json({ limit: '16kb' }));
app.use(session({
    name: 'l1portal.sid',
    store: new PgSessionStore({
        pool,
        createTableIfMissing: false,
        tableName: 'user_sessions'
    }),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        maxAge: 8 * 60 * 60 * 1000
    }
}));
app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
});

const roleSchema = z.enum(['admin', 'viewer']);

function asyncRoute(handler) {
    return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function csrfToken(req) {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    return req.session.csrfToken;
}

function requireCsrf(req, res, next) {
    const token = req.get('X-CSRF-Token');
    const expected = req.session.csrfToken;
    if (!token || !/^[a-f0-9]{64}$/.test(token) || !expected || token.length !== expected.length ||
        !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) {
        return res.status(403).json({ error: 'Invalid or missing CSRF token.' });
    }
    next();
}

const requireAuth = asyncRoute(async (req, res, next) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Authentication required.' });
    }
    const result = await pool.query('SELECT id, email, role FROM users WHERE id = $1', [req.session.user.id]);
    if (!result.rowCount) {
        await new Promise((resolve, reject) => {
            req.session.destroy(error => error ? reject(error) : resolve());
        });
        return res.status(401).json({ error: 'Authentication required.' });
    }
    req.session.user = publicUser(result.rows[0]);
    next();
});

function requireAdmin(req, res, next) {
    if (req.session.user?.role !== 'admin') {
        return res.status(403).json({ error: 'Administrator access required.' });
    }
    next();
}

function publicUser(user) {
    return { id: user.id, email: user.email, role: user.role };
}

app.get('/api/health', asyncRoute(async (req, res) => {
    await pool.query('SELECT 1');
    res.json({ status: 'ok' });
}));

app.get('/api/auth/csrf', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ csrfToken: csrfToken(req) });
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many sign-in attempts. Try again later.' }
});

app.post('/api/auth/login', loginLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const parsedEmail = emailSchema.safeParse(req.body?.email);
    const parsedPassword = z.string().min(1).max(128).safeParse(req.body?.password);
    if (!parsedEmail.success || !parsedPassword.success) {
        return res.status(400).json({ error: 'Enter a valid email address and password.' });
    }

    const result = await pool.query(
        'SELECT id, email, password_hash, role FROM users WHERE email = $1',
        [parsedEmail.data]
    );
    const user = result.rows[0];
    const validPassword = user
        ? await argon2.verify(user.password_hash, parsedPassword.data)
        : await argon2.verify(await DUMMY_PASSWORD_HASH, parsedPassword.data);

    if (!user || !validPassword) {
        return res.status(401).json({ error: 'Invalid email address or password.' });
    }

    await new Promise((resolve, reject) => {
        req.session.regenerate(error => error ? reject(error) : resolve());
    });
    req.session.user = publicUser(user);
    csrfToken(req);
    res.set('Cache-Control', 'no-store');
    res.json({ user: req.session.user });
}));

app.get('/api/auth/me', asyncRoute(async (req, res) => {
    const user = req.session.user;
    if (!user) {
        res.set('Cache-Control', 'no-store');
        return res.json({ user: null });
    }
    const result = await pool.query('SELECT id, email, role FROM users WHERE id = $1', [user.id]);
    if (!result.rowCount) {
        await new Promise((resolve, reject) => {
            req.session.destroy(error => error ? reject(error) : resolve());
        });
        res.set('Cache-Control', 'no-store');
        return res.json({ user: null });
    }
    req.session.user = publicUser(result.rows[0]);
    res.set('Cache-Control', 'no-store');
    res.json({ user: req.session.user });
}));

app.post('/api/auth/logout', requireCsrf, (req, res, next) => {
    req.session.destroy(error => {
        if (error) return next(error);
        res.clearCookie('l1portal.sid', {
            httpOnly: true,
            secure: isProduction,
            sameSite: 'strict'
        });
        res.status(204).end();
    });
});

app.get('/api/users', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
    const result = await pool.query('SELECT id, email, role FROM users ORDER BY email');
    res.set('Cache-Control', 'no-store');
    res.json(result.rows);
}));

app.post('/api/users', requireCsrf, requireAuth, requireAdmin, asyncRoute(async (req, res) => {
    const parsed = z.object({
        email: emailSchema,
        password: passwordSchema,
        role: roleSchema
    }).safeParse(req.body);

    if (!parsed.success) {
        return res.status(400).json({ error: 'Provide a valid email, a password of 12–128 characters, and a valid role.' });
    }

    const passwordHash = await argon2.hash(parsed.data.password, { type: argon2.argon2id });
    try {
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id, email, role',
            [parsed.data.email, passwordHash, parsed.data.role]
        );
        res.status(201).json(publicUser(result.rows[0]));
    } catch (error) {
        if (error.code === '23505') {
            return res.status(409).json({ error: 'A user with that email already exists.' });
        }
        throw error;
    }
}));

app.delete('/api/users/:id', requireCsrf, requireAuth, requireAdmin, asyncRoute(async (req, res) => {
    const id = z.string()
        .regex(/^[1-9]\d{0,18}$/)
        .refine(value => BigInt(value) <= 9223372036854775807n)
        .safeParse(req.params.id);
    if (!id.success) {
        return res.status(400).json({ error: 'Invalid user ID.' });
    }
    if (id.data === String(req.session.user.id)) {
        return res.status(400).json({ error: 'You cannot delete your own account.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query('SELECT pg_advisory_xact_lock($1)', [728113044]);
        const target = await client.query('SELECT id, role FROM users WHERE id = $1 FOR UPDATE', [id.data]);
        if (!target.rowCount) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'User not found.' });
        }
        if (target.rows[0].role === 'admin') {
            const admins = await client.query("SELECT COUNT(*)::int AS count FROM users WHERE role = 'admin'");
            if (admins.rows[0].count <= 1) {
                await client.query('ROLLBACK');
                return res.status(409).json({ error: 'The last administrator cannot be deleted.' });
            }
        }
        await client.query('DELETE FROM users WHERE id = $1', [id.data]);
        await client.query('COMMIT');
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }
    res.status(204).end();
}));

app.get('/api/links', requireAuth, asyncRoute(async (req, res) => {
    const result = await pool.query(
        'SELECT id, title, category, tag, dc_url AS "dcUrl", dr_url AS "drUrl", description AS "desc", icon FROM portal_links ORDER BY id'
    );
    res.set('Cache-Control', 'no-store');
    res.json(result.rows);
}));

app.post('/api/links', requireCsrf, requireAuth, requireAdmin, asyncRoute(async (req, res) => {
    const parsed = linkSchema.safeParse(req.body);
    if (!parsed.success) {
        return res.status(400).json({ error: 'Provide a title, category, valid DC URL, and valid optional DR URL.' });
    }

    const link = parsed.data;
    const result = await pool.query(
        `INSERT INTO portal_links (title, category, tag, dc_url, dr_url, description, icon)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, title, category, tag, dc_url AS "dcUrl", dr_url AS "drUrl",
                   description AS "desc", icon`,
        [link.title, link.category, link.tag, link.dcUrl, link.drUrl, link.desc, link.icon]
    );
    res.status(201).json(result.rows[0]);
}));

app.get('/', (req, res) => res.sendFile(path.join(projectDir, 'l1_portal_client.html')));
app.get('/l1_portal_client.html', (req, res) => res.sendFile(path.join(projectDir, 'l1_portal_client.html')));
app.get('/auth.js', (req, res) => res.sendFile(path.join(projectDir, 'auth.js')));
app.get('/app.css', (req, res) => res.sendFile(path.join(projectDir, 'public', 'app.css')));

app.use((error, req, res, next) => {
    console.error('Request failed:', error);
    if (res.headersSent) return next(error);
    const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 500
        ? error.status
        : 500;
    res.status(status).json({
        error: status === 500 ? 'An unexpected server error occurred.' : error.message
    });
});

let server;
const DUMMY_PASSWORD_HASH = argon2.hash(crypto.randomBytes(32).toString('hex'), { type: argon2.argon2id });

async function initializeDatabase() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS user_sessions (
            sid VARCHAR NOT NULL PRIMARY KEY,
            sess JSON NOT NULL,
            expire TIMESTAMP(6) NOT NULL
        );
        CREATE INDEX IF NOT EXISTS IDX_user_sessions_expire ON user_sessions (expire);
        CREATE TABLE IF NOT EXISTS portal_links (
            id BIGSERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            tag TEXT NOT NULL DEFAULT 'Custom',
            dc_url TEXT NOT NULL,
            dr_url TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            icon TEXT NOT NULL DEFAULT 'fa-link',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);

    const linksPath = path.join(projectDir, 'portal-data.json');
    const initialLinks = JSON.parse(await fs.readFile(linksPath, 'utf8'));
    if (!Array.isArray(initialLinks)) {
        throw new Error('portal-data.json must contain a JSON array.');
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        for (const rawLink of initialLinks) {
            const parsedLink = linkSchema.safeParse(rawLink);
            const id = z.coerce.number().int().positive().safeParse(rawLink?.id);
            if (!parsedLink.success || !id.success) {
                throw new Error(`Invalid portal link record with ID ${rawLink?.id ?? 'unknown'}.`);
            }
            const link = parsedLink.data;
            await client.query(
                `INSERT INTO portal_links (id, title, category, tag, dc_url, dr_url, description, icon)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (id) DO NOTHING`,
                [id.data, link.title, link.category, link.tag, link.dcUrl, link.drUrl, link.desc, link.icon]
            );
        }
        await client.query(`
            SELECT setval(
                pg_get_serial_sequence('portal_links', 'id')::regclass,
                GREATEST(COALESCE((SELECT MAX(id) FROM portal_links), 1), 1),
                EXISTS (SELECT 1 FROM portal_links)
            )
        `);
        await client.query('COMMIT');
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }

    const userCount = await pool.query('SELECT COUNT(*)::int AS count FROM users');
    if (userCount.rows[0].count === 0) {
        const email = emailSchema.safeParse(process.env.BOOTSTRAP_ADMIN_EMAIL);
        const password = passwordSchema.safeParse(process.env.BOOTSTRAP_ADMIN_PASSWORD);
        if (!email.success || !password.success) {
            throw new Error('No users exist. Set valid BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD to create the first administrator.');
        }
        const hash = await argon2.hash(password.data, { type: argon2.argon2id });
        await pool.query(
            'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)',
            [email.data, hash, 'admin']
        );
        console.info(`Created initial administrator account: ${email.data}`);
    }
}

async function start() {
    await initializeDatabase();
    server = app.listen(port, () => {
        console.info(`L1 Portal server listening on port ${port}.`);
    });
}

async function shutdown(signal) {
    console.info(`${signal} received; shutting down.`);
    if (server) {
        await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
    await pool.end();
    process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT').catch(error => {
    console.error('Shutdown failed:', error);
    process.exit(1);
}));
process.on('SIGTERM', () => shutdown('SIGTERM').catch(error => {
    console.error('Shutdown failed:', error);
    process.exit(1);
}));

start().catch(async error => {
    console.error('Startup failed:', error);
    await pool.end();
    process.exit(1);
});
