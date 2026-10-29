const { z } = require('zod');

const emailSchema = z.string().trim().email().max(254).transform(value => value.toLowerCase());
const passwordSchema = z.string().min(12).max(128);
const roleSchema = z.enum(['admin', 'viewer']);
const linkUrlSchema = z.string().trim().max(2048).refine(value => {
    try {
        const protocol = new URL(value).protocol;
        return protocol === 'http:' || protocol === 'https:';
    } catch {
        return false;
    }
}, 'Only HTTP and HTTPS URLs are allowed.');
const linkSchema = z.object({
    title: z.string().trim().min(1).max(160),
    category: z.enum(['Monitoring', 'Enterprise', 'Gateway', 'Switch', 'Admin', 'SMS', 'Other']),
    tag: z.string().trim().max(60).optional().default('Custom'),
    dcUrl: linkUrlSchema,
    drUrl: z.union([linkUrlSchema, z.literal('')]).optional().default(''),
    desc: z.string().trim().max(1000).optional().default(''),
    icon: z.string().trim().regex(/^fa-[a-z0-9-]+$/).max(80).optional().default('fa-link')
});

module.exports = { emailSchema, passwordSchema, roleSchema, linkSchema };
