const test = require('node:test');
const assert = require('node:assert/strict');
const { emailSchema, passwordSchema, roleSchema, linkSchema } = require('../lib/validation');

test('email addresses are normalized and malformed addresses are rejected', () => {
    assert.equal(emailSchema.parse('  ADMIN@example.com '), 'admin@example.com');
    assert.equal(emailSchema.safeParse('not-an-email').success, false);
});

test('password policy requires 12 to 128 characters', () => {
    assert.equal(passwordSchema.safeParse('short').success, false);
    assert.equal(passwordSchema.safeParse('a-secure-password').success, true);
    assert.equal(passwordSchema.safeParse('a'.repeat(129)).success, false);
});

test('roles are restricted to the supported role set', () => {
    assert.equal(roleSchema.safeParse('admin').success, true);
    assert.equal(roleSchema.safeParse('viewer').success, true);
    assert.equal(roleSchema.safeParse('owner').success, false);
});

test('portal links accept HTTP(S) and reject unsafe protocols and categories', () => {
    const link = {
        title: 'Operations',
        category: 'Monitoring',
        dcUrl: 'http://10.0.0.1/monitor'
    };
    assert.equal(linkSchema.safeParse(link).success, true);
    assert.equal(linkSchema.safeParse({ ...link, dcUrl: 'javascript://example.com' }).success, false);
    assert.equal(linkSchema.safeParse({ ...link, category: 'Unknown' }).success, false);
});
