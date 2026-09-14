import express from 'express';

const app = express();
const port = Number(process.env.PORT || 3000);
const supabaseUrl = String(process.env.SUPABASE_URL || '').replace(/\/$/, '');
const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const supabaseBucket = process.env.SUPABASE_BUCKET || 'school-files';

app.use(express.json({ limit: '50mb' }));
app.use(express.static('.'));

const safeUploadKey = (key = '') => String(key || '').replace(/^\/+/, '').replace(/\\/g, '/');

const supabaseRequest = async (path, options = {}) => {
    if (!supabaseUrl || !supabaseSecretKey) {
        throw new Error('Supabase environment variables are not configured.');
    }
    const response = await fetch(`${supabaseUrl}/rest/v1/${path}`, {
        ...options,
        headers: {
            apikey: supabaseSecretKey,
            Authorization: `Bearer ${supabaseSecretKey}`,
            'Content-Type': 'application/json',
            ...(options.headers || {})
        }
    });
    if (!response.ok) {
        const detail = await response.text();
        throw new Error(`Supabase request failed (${response.status}): ${detail}`);
    }
    return response.status === 204 ? null : response.json();
};

const supabaseStorageUpload = async (key, data, contentType = 'application/octet-stream') => {
    if (!supabaseUrl || !supabaseSecretKey) {
        throw new Error('Supabase environment variables are not configured.');
    }

    const safeKey = safeUploadKey(key);
    const response = await fetch(`${supabaseUrl}/storage/v1/object/${supabaseBucket}/${encodeURIComponent(safeKey)}`, {
        method: 'POST',
        headers: {
            apikey: supabaseSecretKey,
            Authorization: `Bearer ${supabaseSecretKey}`,
            'Content-Type': contentType,
            'x-upsert': 'true'
        },
        body: data instanceof Buffer ? data : Buffer.from(data)
    });

    const responseText = await response.text();
    if (!response.ok) {
        throw new Error(`Supabase storage upload failed (${response.status}): ${responseText}`);
    }

    return {
        key: safeKey,
        url: `${supabaseUrl}/storage/v1/object/public/${supabaseBucket}/${safeKey}`,
        storageUrl: `${supabaseUrl}/storage/v1/object/${supabaseBucket}/${safeKey}`
    };
};

app.get('/api/storage', async (_request, response) => {
    try {
        const rows = await supabaseRequest('school_storage?id=eq.main&select=data');
        response.json({ data: rows[0]?.data || null });
    } catch (error) {
        console.error(error);
        response.status(503).json({ error: 'Cloud storage is not configured or unavailable.' });
    }
});

app.put('/api/storage', async (request, response) => {
    if (!request.body || typeof request.body.data !== 'object' || Array.isArray(request.body.data)) {
        response.status(400).json({ error: 'Storage data must be a JSON object.' });
        return;
    }
    try {
        await supabaseRequest('school_storage?on_conflict=id', {
            method: 'POST',
            headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
            body: JSON.stringify({ id: 'main', data: request.body.data })
        });
        response.status(204).end();
    } catch (error) {
        console.error(error);
        response.status(503).json({ error: 'Cloud storage is not configured or unavailable.' });
    }
});

app.post('/api/upload', async (request, response) => {
    try {
        const { key, fileName, mimeType, data } = request.body || {};
        if (!key || !data) {
            response.status(400).json({ error: 'Upload payload must include a key and file data.' });
            return;
        }

        const normalizedKey = safeUploadKey(key);
        const contentType = mimeType || 'application/octet-stream';
        const rawData = typeof data === 'string' && data.includes('base64,') ? data.split('base64,')[1] || data : data;
        const uploadBuffer = Buffer.from(String(rawData), 'base64');

        const result = await supabaseStorageUpload(normalizedKey, uploadBuffer, contentType);
        response.json({
            key: result.key,
            url: result.url,
            fileName: fileName || normalizedKey.split('/').pop(),
            mimeType: contentType
        });
    } catch (error) {
        console.error(error);
        response.status(503).json({ error: 'File upload to Supabase failed.' });
    }
});

app.listen(port, () => {
    console.log(`System Data School server listening on port ${port}`);
});
