const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const request = require('supertest');

process.env.DATABASE_URL = 'postgresql://unused:unused@127.0.0.1:1/l1portal_test';
process.env.SESSION_SECRET = crypto.randomBytes(48).toString('base64');
process.env.NODE_ENV = 'test';

const { app, pool } = require('../server');

test('liveness probe responds without querying PostgreSQL', async () => {
    try {
        const response = await request(app).get('/api/health/live').expect(200);
        assert.deepEqual(response.body, { status: 'ok' });
        assert.ok(response.headers['x-request-id']);
    } finally {
        await pool.end();
    }
});
