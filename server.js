import express from 'express';
import crypto from 'node:crypto';

const app = express();
const port = Number(process.env.PORT || 3000);
const supabaseUrl = String(process.env.SUPABASE_URL || '').replace(/\/$/, '');
const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || '';
const ownerUsername = process.env.OWNER_USERNAME || 'owner';
const ownerPassword = process.env.OWNER_PASSWORD || '@Seyha1525@';
const supabaseBucket = process.env.SUPABASE_BUCKET || 'school-files';

app.use(express.json({ limit: '50mb' }));
app.use(express.static('.'));

app.get('/api/health', (_request, response) => {
    const missing = [];
    if (!supabaseUrl) missing.push('SUPABASE_URL');
    if (!supabaseSecretKey) missing.push('SUPABASE_SECRET_KEY');
    response.json({ ok: true, supabaseConfigured: Boolean(supabaseUrl && supabaseSecretKey), bucketConfigured: Boolean(supabaseBucket), missing });
});

// Supabase REST is the only database boundary for accounts and school data.
const safeUploadKey = (key = '') => String(key || '').replace(/^\/+/, '').replace(/\\/g, '/');
const supabaseRequest = async (path, options = {}) => {
    if (!supabaseUrl || !supabaseSecretKey) throw new Error('Supabase environment variables are not configured.');
    const response = await fetch(`${supabaseUrl}/rest/v1/${path}`, {
        ...options,
        headers: { apikey: supabaseSecretKey, Authorization: 'Bearer ' + supabaseSecretKey, 'Content-Type': 'application/json', ...(options.headers || {}) }
    });
    if (!response.ok) throw new Error(`Supabase request failed (${response.status}): ${await response.text()}`);
    const body = await response.text();
    return body ? JSON.parse(body) : null;
};

const hashPassword = (password) => {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
    return `${salt}:${hash}`;
};
const verifyPassword = (password, storedHash) => {
    const [salt, expected] = String(storedHash || '').split(':');
    if (!salt || !expected) return false;
    const actual = crypto.scryptSync(String(password), salt, 64);
    const expectedBuffer = Buffer.from(expected, 'hex');
    return expectedBuffer.length === actual.length && crypto.timingSafeEqual(actual, expectedBuffer);
};
const normalizeUsername = (username) => String(username || '').trim();
const findManagedAccount = async (username) => {
    const encodedUsername = encodeURIComponent(normalizeUsername(username));
    const rows = await supabaseRequest(`managed_accounts?username=eq.${encodedUsername}&select=username,role,password_hash&limit=1`);
    return rows[0] || null;
};
const saveManagedAccount = async (username, password, role, createdBy) => {
    if (await findManagedAccount(username)) {
        const error = new Error('USERNAME_EXISTS');
        error.code = 'USERNAME_EXISTS';
        throw error;
    }
    await supabaseRequest('managed_accounts?on_conflict=username', {
        method: 'POST',
        headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
        body: JSON.stringify({ username, password_hash: hashPassword(password), role, created_by: createdBy })
    });
};
const resetManagedAccountPassword = async (username, password) => {
    const encodedUsername = encodeURIComponent(username);
    await supabaseRequest(`managed_accounts?username=eq.${encodedUsername}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=minimal' },
        body: JSON.stringify({ password_hash: hashPassword(password) })
    });
};
const verifyOwnerPassword = (username, password) => username === ownerUsername && password === ownerPassword;
const verifyAdminPassword = async (username, password) => {
    const account = await findManagedAccount(username);
    return account?.role === 'admin' && verifyPassword(password, account.password_hash);
};

app.post('/api/role-login', async (request, response) => {
    const username = normalizeUsername(request.body?.username);
    const password = String(request.body?.password || '');
    try {
        if (verifyOwnerPassword(username, password)) return response.json({ role: 'owner' });
        if (await verifyAdminPassword(username, password)) return response.json({ role: 'admin' });
        const account = await findManagedAccount(username);
        if (account?.role === 'user' && verifyPassword(password, account.password_hash)) return response.json({ role: 'user' });
        response.status(401).json({ error: 'Invalid credentials.' });
    } catch (error) {
        console.error('Role login failed.', error);
        response.status(503).json({ error: 'Account storage is unavailable. Please try again later.' });
    }
});

app.post('/api/managed-user-credentials', async (request, response) => {
    const { creatorRole, creatorUsername, creatorPassword } = request.body || {};
    const username = normalizeUsername(request.body?.username);
    const password = String(request.body?.password || '');
    try {
        const authorized = creatorRole === 'owner'
            ? creatorPassword === ownerPassword
            : creatorRole === 'admin' && await verifyAdminPassword(normalizeUsername(creatorUsername), creatorPassword);
        if (!authorized) return response.status(401).json({ error: 'Only Owner or Admin can create a User account.' });
        if (!username || password.length < 8) return response.status(400).json({ error: 'Username and a password of at least 8 characters are required.' });
        await saveManagedAccount(username, password, 'user', creatorRole);
        response.json({ ok: true });
    } catch (error) {
        if (error.code === 'USERNAME_EXISTS') return response.status(409).json({ error: 'Username នេះមានរួចហើយ។ សូមជ្រើស Username ផ្សេង។' });
        console.error('User account creation failed.', error);
        response.status(503).json({ error: 'Account storage is unavailable. Please try again later.' });
    }
});

app.post('/api/owner/admin-credentials', async (request, response) => {
    const { ownerPassword: suppliedOwnerPassword } = request.body || {};
    const username = normalizeUsername(request.body?.username);
    const password = String(request.body?.password || '');
    if (!verifyOwnerPassword(ownerUsername, suppliedOwnerPassword)) return response.status(401).json({ error: 'Owner authentication failed.' });
    if (!username || password.length < 8) return response.status(400).json({ error: 'Admin username and a password of at least 8 characters are required.' });
    try {
        await saveManagedAccount(username, password, 'admin', 'owner');
        response.json({ ok: true });
    } catch (error) {
        if (error.code === 'USERNAME_EXISTS') return response.status(409).json({ error: 'Username នេះមានរួចហើយ។ សូមជ្រើស Username ផ្សេង។' });
        console.error('Admin account creation failed.', error);
        response.status(503).json({ error: 'Account storage is unavailable. Please try again later.' });
    }
});

app.post('/api/reset-managed-password', async (request, response) => {
    const { creatorRole, creatorUsername, creatorPassword, targetUsername } = request.body || {};
    const target = normalizeUsername(targetUsername);
    const newPassword = String(request.body?.newPassword || '');
    if (!target || newPassword.length < 8) {
        response.status(400).json({ error: 'Username និង password ថ្មីយ៉ាងតិច 8 តួអក្សរត្រូវបានទាមទារ។' });
        return;
    }
    try {
        const account = await findManagedAccount(target);
        if (!account) return response.status(404).json({ error: 'រកមិនឃើញ account នេះទេ។' });
        const creatorAuthorized = creatorRole === 'owner'
            ? creatorPassword === ownerPassword
            : creatorRole === 'admin' && await verifyAdminPassword(normalizeUsername(creatorUsername), creatorPassword);
        const allowedTarget = creatorRole === 'owner' || (creatorRole === 'admin' && account.role === 'user');
        if (!creatorAuthorized || !allowedTarget) {
            response.status(403).json({ error: 'សិទ្ធិរបស់អ្នកមិនអាច reset account នេះបានទេ។' });
            return;
        }
        await resetManagedAccountPassword(target, newPassword);
        response.json({ ok: true });
    } catch (error) {
        console.error('Managed password reset failed.', error);
        response.status(503).json({ error: 'Account storage is unavailable. Please try again later.' });
    }
});

const supabaseStorageUpload = async (key, data, contentType = 'application/octet-stream') => {
    if (!supabaseUrl || !supabaseSecretKey) throw new Error('Supabase environment variables are not configured.');
    const safeKey = safeUploadKey(key);
    const encodedKey = safeKey.split('/').map(segment => encodeURIComponent(segment)).join('/');
    const response = await fetch(`${supabaseUrl}/storage/v1/object/${supabaseBucket}/${encodedKey}`, {
        method: 'POST',
        headers: { apikey: supabaseSecretKey, Authorization: 'Bearer ' + supabaseSecretKey, 'Content-Type': contentType, 'x-upsert': 'true' },
        body: data instanceof Buffer ? data : Buffer.from(data)
    });
    if (!response.ok) throw new Error(`Supabase storage upload failed (${response.status}): ${await response.text()}`);
    return { key: safeKey, url: `${supabaseUrl}/storage/v1/object/public/${supabaseBucket}/${safeKey}` };
};

app.get('/api/storage', async (_request, response) => {
    try {
        const rows = await supabaseRequest('school_storage?id=eq.main&select=data');
        response.json({ data: rows[0]?.data || null });
    } catch (error) {
        console.error(error);
        response.status(503).json({ error: 'Cloud storage is not configured or unavailable.', detail: error.message });
    }
});

app.put('/api/storage', async (request, response) => {
    if (!request.body || typeof request.body.data !== 'object' || Array.isArray(request.body.data)) {
        response.status(400).json({ error: 'Storage data must be a JSON object.' });
        return;
    }
    try {
        await supabaseRequest('school_storage?on_conflict=id', { method: 'POST', headers: { Prefer: 'resolution=merge-duplicates,return=minimal' }, body: JSON.stringify({ id: 'main', data: request.body.data }) });
        response.status(204).end();
    } catch (error) {
        console.error(error);
        response.status(503).json({ error: 'Cloud storage is not configured or unavailable.', detail: error.message });
    }
});

app.post('/api/upload', async (request, response) => {
    try {
        const { key, fileName, mimeType, data } = request.body || {};
        if (!key || !data) return response.status(400).json({ error: 'Upload payload must include a key and file data.' });
        const rawData = typeof data === 'string' && data.includes('base64,') ? data.split('base64,')[1] || data : data;
        const result = await supabaseStorageUpload(key, Buffer.from(String(rawData), 'base64'), mimeType || 'application/octet-stream');
        response.json({ key: result.key, url: result.url, fileName: fileName || result.key.split('/').pop(), mimeType: mimeType || 'application/octet-stream' });
    } catch (error) {
        console.error(error);
        response.status(503).json({ error: 'File upload to Supabase failed.', detail: error.message });
    }
});

app.listen(port, () => console.log(`System Data School server listening on port ${port}`));
