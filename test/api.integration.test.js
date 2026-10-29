const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
require('dotenv').config();
const { Pool } = require('pg');
const request = require('supertest');

test('authentication, password management, authorization, and portal API flows', {
    skip: !process.env.TEST_DATABASE_URL && 'Set TEST_DATABASE_URL to run PostgreSQL integration tests.'
}, async () => {
    const testDatabaseUrl = process.env.TEST_DATABASE_URL;
    const runtimeDatabaseUrl = process.env.DATABASE_URL;
    const testDatabase = new URL(testDatabaseUrl);
    if (runtimeDatabaseUrl) {
        const runtimeDatabase = new URL(runtimeDatabaseUrl);
        assert.notEqual(
            decodeURIComponent(testDatabase.pathname),
            decodeURIComponent(runtimeDatabase.pathname),
            'TEST_DATABASE_URL must use a separate database from DATABASE_URL.'
        );
    }

    const schema = `l1portal_test_${crypto.randomBytes(8).toString('hex')}`;
    const databaseAdminPool = new Pool({ connectionString: testDatabaseUrl });
    let appPool;
    let schemaCreated = false;
    try {
        await databaseAdminPool.query(`CREATE SCHEMA "${schema}"`);
        schemaCreated = true;
        const scopedDatabaseUrl = new URL(testDatabaseUrl);
        scopedDatabaseUrl.searchParams.set('options', `-c search_path=${schema}`);
        process.env.DATABASE_URL = scopedDatabaseUrl.toString();
        process.env.NODE_ENV = 'test';
        process.env.SESSION_SECRET = crypto.randomBytes(48).toString('base64');
        process.env.BOOTSTRAP_ADMIN_EMAIL = 'admin@example.test';
        process.env.BOOTSTRAP_ADMIN_PASSWORD = 'integration-admin-password-123';

        const { app, pool, initializeDatabase } = require('../server');
        appPool = pool;
        await initializeDatabase();

        const admin = request.agent(app);
        const csrfFor = async agent => {
            const response = await agent.get('/api/auth/csrf').expect(200);
            return response.body.csrfToken;
        };

        await request(app).get('/api/health/live').expect(200, { status: 'ok' });
        await request(app).get('/api/health/ready').expect(200, { status: 'ready' });
        await admin.get('/api/users').expect(401);

        let csrf = await csrfFor(admin);
        await admin.post('/api/auth/login')
            .send({ email: process.env.BOOTSTRAP_ADMIN_EMAIL, password: process.env.BOOTSTRAP_ADMIN_PASSWORD })
            .expect(403);
        await admin.post('/api/auth/login')
            .set('X-CSRF-Token', csrf)
            .send({ email: process.env.BOOTSTRAP_ADMIN_EMAIL, password: 'incorrect-password' })
            .expect(401);
        await admin.post('/api/auth/login')
            .set('X-CSRF-Token', csrf)
            .send({ email: process.env.BOOTSTRAP_ADMIN_EMAIL, password: process.env.BOOTSTRAP_ADMIN_PASSWORD })
            .expect(200);
        csrf = await csrfFor(admin);

        const createdUser = await admin.post('/api/users')
            .set('X-CSRF-Token', csrf)
            .send({
                email: 'viewer@example.test',
                password: 'viewer-password-123',
                role: 'viewer'
            })
            .expect(201);
        assert.equal(createdUser.body.role, 'viewer');
        assert.equal(Object.hasOwn(createdUser.body, 'password_hash'), false);
        const adminUser = (await admin.get('/api/users').expect(200)).body
            .find(user => user.email === process.env.BOOTSTRAP_ADMIN_EMAIL);
        assert.ok(adminUser);

        const viewer = request.agent(app);
        let viewerCsrf = await csrfFor(viewer);
        await viewer.post('/api/auth/login')
            .set('X-CSRF-Token', viewerCsrf)
            .send({ email: 'viewer@example.test', password: 'viewer-password-123' })
            .expect(200);
        await viewer.get('/api/users').expect(403);

        const viewerOtherSession = request.agent(app);
        let viewerOtherCsrf = await csrfFor(viewerOtherSession);
        await viewerOtherSession.post('/api/auth/login')
            .set('X-CSRF-Token', viewerOtherCsrf)
            .send({ email: 'viewer@example.test', password: 'viewer-password-123' })
            .expect(200);

        viewerCsrf = await csrfFor(viewer);
        await viewer.post('/api/auth/change-password')
            .send({ oldPassword: 'viewer-password-123', newPassword: 'viewer-updated-password-456' })
            .expect(403);
        await viewer.post('/api/auth/change-password')
            .set('X-CSRF-Token', viewerCsrf)
            .send({ oldPassword: 'wrong-current-password', newPassword: 'viewer-updated-password-456' })
            .expect(401);
        const changePasswordResponse = await viewer.post('/api/auth/change-password')
            .set('X-CSRF-Token', viewerCsrf)
            .send({ oldPassword: 'viewer-password-123', newPassword: 'viewer-updated-password-456' })
            .expect(200);
        assert.match(changePasswordResponse.body.message, /Sign in again/);
        const sessionsAfterOwnPasswordChange = await pool.query(
            "SELECT COUNT(*)::int AS count FROM user_sessions WHERE sess->'user'->>'id' = $1",
            [String(createdUser.body.id)]
        );
        assert.equal(sessionsAfterOwnPasswordChange.rows[0].count, 0);
        await viewer.get('/api/auth/me').expect(200, { user: null });
        await viewer.get('/api/links').expect(401);
        await viewerOtherSession.get('/api/auth/me').expect(200, { user: null });

        const viewerUpdatedPasswordSession = request.agent(app);
        viewerCsrf = await csrfFor(viewerUpdatedPasswordSession);
        await viewerUpdatedPasswordSession.post('/api/auth/login')
            .set('X-CSRF-Token', viewerCsrf)
            .send({ email: 'viewer@example.test', password: 'viewer-updated-password-456' })
            .expect(200);

        let adminCsrf = await csrfFor(admin);
        const sessionsBeforeAdminReset = await pool.query(
            "SELECT COUNT(*)::int AS count FROM user_sessions WHERE sess->'user'->>'id' = $1",
            [String(createdUser.body.id)]
        );
        assert.ok(sessionsBeforeAdminReset.rows[0].count >= 2);
        await admin.post(`/api/users/${createdUser.body.id}/password`)
            .set('X-CSRF-Token', adminCsrf)
            .send({ password: 'viewer-temporary-password-789' })
            .expect(200);
        const sessionsAfterAdminReset = await pool.query(
            "SELECT COUNT(*)::int AS count FROM user_sessions WHERE sess->'user'->>'id' = $1",
            [String(createdUser.body.id)]
        );
        assert.equal(sessionsAfterAdminReset.rows[0].count, 0);
        await viewer.get('/api/auth/me').expect(200, { user: null });
        await viewer.get('/api/links').expect(401);
        await viewerUpdatedPasswordSession.get('/api/auth/me').expect(200, { user: null });
        await viewerUpdatedPasswordSession.get('/api/links').expect(401);

        const viewerAfterAdminReset = request.agent(app);
        viewerCsrf = await csrfFor(viewerAfterAdminReset);
        await viewerAfterAdminReset.post('/api/auth/login')
            .set('X-CSRF-Token', viewerCsrf)
            .send({ email: 'viewer@example.test', password: 'viewer-updated-password-456' })
            .expect(401);
        await viewerAfterAdminReset.post('/api/auth/login')
            .set('X-CSRF-Token', viewerCsrf)
            .send({ email: 'viewer@example.test', password: 'viewer-temporary-password-789' })
            .expect(200);
        viewerCsrf = await csrfFor(viewerAfterAdminReset);

        await admin.post(`/api/users/${createdUser.body.id}/password`)
            .set('X-CSRF-Token', adminCsrf)
            .send({ password: 'short' })
            .expect(400);
        await admin.post(`/api/users/${adminUser.id}/password`)
            .set('X-CSRF-Token', adminCsrf)
            .send({ password: 'admin-own-reset-password-123' })
            .expect(400);
        await admin.post(`/api/users/999999999/password`)
            .set('X-CSRF-Token', adminCsrf)
            .send({ password: 'nonexistent-reset-password' })
            .expect(404);

        const viewerCannotReset = await viewerAfterAdminReset.post(`/api/users/${createdUser.body.id}/password`)
            .set('X-CSRF-Token', viewerCsrf)
            .send({ password: 'viewer-forbidden-reset-123' });
        assert.equal(viewerCannotReset.status, 403);

        const linksBefore = await admin.get('/api/links').expect(200);
        assert.ok(linksBefore.body.length > 0);
        const createdLink = await admin.post('/api/links')
            .set('X-CSRF-Token', adminCsrf)
            .send({
                title: 'Integration test link',
                category: 'Other',
                dcUrl: 'https://example.test/portal'
            })
            .expect(201);
        assert.equal(createdLink.body.title, 'Integration test link');

        await admin.delete(`/api/users/${createdUser.body.id}`)
            .set('X-CSRF-Token', adminCsrf)
            .expect(204);
        await viewerAfterAdminReset.get('/api/auth/me').expect(200, { user: null });

        await admin.post('/api/auth/logout')
            .set('X-CSRF-Token', adminCsrf)
            .expect(204);
        await admin.get('/api/auth/me').expect(200, { user: null });
    } finally {
        try {
            if (appPool) {
                await appPool.end();
            }
        } finally {
            try {
                if (schemaCreated) {
                    await databaseAdminPool.query(`DROP SCHEMA "${schema}" CASCADE`);
                }
            } finally {
                await databaseAdminPool.end();
            }
        }
    }
});
