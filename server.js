const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const db = require('./database');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

// Comptes admin : { nom: motdepasse }
const ADMIN_ACCOUNTS = {
    'Gravity': process.env.ADMIN_PASSWORD || 'admin_gravity',
    'Brodie':  process.env.BRODIE_PASSWORD || 'admin_brodie'
};

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Bypass localtunnel interstitial page
app.use((req, res, next) => {
    res.setHeader('bypass-tunnel-reminder', 'true');
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Health check endpoint
app.get('/ping', (req, res) => res.send('OK'));

// Middleware to check admin password
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const found = Object.entries(ADMIN_ACCOUNTS).find(([name, pass]) => pass === authHeader);
    if (found) {
        req.adminName = found[0]; // 'Gravity' or 'Brodie'
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

// Endpoint to get current admin identity
app.get('/api/admin/me', authMiddleware, (req, res) => {
    res.json({ name: req.adminName });
});

// Helper to get settings
const getSettings = (callback) => {
    db.all('SELECT key, value FROM settings', [], (err, rows) => {
        if (err) return callback(err);
        const settings = {
            allowRegistration: true,
            autoApprove: true,
            trialDays: 3,
            fusion_allowRegistration: true,
            fusion_autoApprove: true,
            fusion_trialDays: 3
        };
        if (rows) {
            rows.forEach(r => {
                if (r.key === 'allowRegistration') settings.allowRegistration = r.value === 'true';
                if (r.key === 'autoApprove') settings.autoApprove = r.value === 'true';
                if (r.key === 'trialDays') settings.trialDays = parseInt(r.value, 10) || 0;
                
                if (r.key === 'fusion_allowRegistration') settings.fusion_allowRegistration = r.value === 'true';
                if (r.key === 'fusion_autoApprove') settings.fusion_autoApprove = r.value === 'true';
                if (r.key === 'fusion_trialDays') settings.fusion_trialDays = parseInt(r.value, 10) || 0;
            });
        }
        callback(null, settings);
    });
};

// -- CLIENT HANDSHAKE API --
const ADMIN_HWID = '228c0b959e0f41d9';

app.get(['/api/auth', '/api/fusi'], (req, res) => {
    const hwid = req.query.hwid;
    const isFusionRoute = req.path === '/api/fusi';
    const defaultSource = isFusionRoute ? 'FUSION' : 'V10PAYANTPROPATCH';
    const source = req.query.source || defaultSource;
    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const ip = rawIp.split(',')[0].trim();

    if (!hwid) {
        return res.status(400).send('error');
    }

    getSettings((err, settings) => {
        if (err) return res.status(500).send('error');

        db.get('SELECT * FROM devices WHERE hwid = ?', [hwid], (err, row) => {
            if (err) return res.status(500).send('error');

            if (row) {
                // Update last seen, IP & source
                db.run('UPDATE devices SET last_seen = CURRENT_TIMESTAMP, last_ip = ?, app_source = ? WHERE hwid = ?', [ip, source, hwid]);
                db.run('INSERT INTO ip_history (hwid, ip) VALUES (?, ?)', [hwid, ip]);

                if (hwid !== ADMIN_HWID && row.status === 'banned') {
                    return res.send('banned');
                }

                if (hwid !== ADMIN_HWID && row.expires_at) {
                    const expiry = new Date(row.expires_at).getTime();
                    if (Date.now() > expiry) {
                        return res.send('expired');
                    }
                }

                return res.send('allowed');
            } else {
                const isFusion = source === 'FUSION';
                const sAllowReg = isFusion ? settings.fusion_allowRegistration : settings.allowRegistration;
                const sAutoApprove = isFusion ? settings.fusion_autoApprove : settings.autoApprove;
                const sTrialDays = isFusion ? settings.fusion_trialDays : settings.trialDays;

                if (!sAllowReg && hwid !== ADMIN_HWID) {
                    return res.send('banned');
                }

                const status = (sAutoApprove || hwid === ADMIN_HWID) ? 'allowed' : 'pending';
                let expiresAt = null;
                if (sTrialDays > 0) {
                    expiresAt = new Date(Date.now() + sTrialDays * 86400000).toISOString();
                }

                db.run('INSERT INTO devices (hwid, label, status, expires_at, app_source) VALUES (?, ?, ?, ?, ?)', [hwid, 'Nouveau Client', status, expiresAt, source], (err) => {
                    if (err) return res.status(500).send('error');
                    db.run('INSERT INTO ip_history (hwid, ip) VALUES (?, ?)', [hwid, ip]);
                    return res.send(status);
                });
            }
        });
    });
});

app.post(['/api/auth', '/api/fusi'], (req, res) => {
    const { hwid, source: bodySource } = req.body;
    const isFusionRoute = req.path === '/api/fusi';
    const defaultSource = isFusionRoute ? 'FUSION' : 'V10PAYANTPROPATCH';
    const source = bodySource || req.query.source || defaultSource;
    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const ip = rawIp.split(',')[0].trim();

    if (!hwid) {
        return res.status(400).json({ status: 'error', message: 'HWID is required' });
    }

    getSettings((err, settings) => {
        if (err) return res.status(500).json({ status: 'error', message: 'Settings error' });

        db.get('SELECT * FROM devices WHERE hwid = ?', [hwid], (err, row) => {
            if (err) return res.status(500).json({ status: 'error', message: 'Database error' });

            if (row) {
                // Update last seen, IP & source
                db.run('UPDATE devices SET last_seen = CURRENT_TIMESTAMP, last_ip = ?, app_source = ? WHERE hwid = ?', [ip, source, hwid]);
                db.run('INSERT INTO ip_history (hwid, ip) VALUES (?, ?)', [hwid, ip]);

                if (hwid !== ADMIN_HWID && row.status === 'banned') {
                    return res.json({ status: 'banned', message: 'Votre appareil est banni de ce mod menu.' });
                }

                if (hwid !== ADMIN_HWID && row.expires_at) {
                    const expiry = new Date(row.expires_at).getTime();
                    if (Date.now() > expiry) {
                        return res.json({ status: 'expired', message: 'Votre licence a expiré. Veuillez la renouveler.' });
                    }
                }

                return res.json({ status: 'allowed', message: 'Welcome!', expiresAt: row.expires_at || null });
            } else {
                const isFusion = source === 'FUSION';
                const sAllowReg = isFusion ? settings.fusion_allowRegistration : settings.allowRegistration;
                const sAutoApprove = isFusion ? settings.fusion_autoApprove : settings.autoApprove;
                const sTrialDays = isFusion ? settings.fusion_trialDays : settings.trialDays;

                if (!sAllowReg && hwid !== ADMIN_HWID) {
                    return res.json({ status: 'banned', message: 'Les nouvelles inscriptions sont désactivées.' });
                }

                const status = (sAutoApprove || hwid === ADMIN_HWID) ? 'allowed' : 'pending';
                let expiresAt = null;
                if (sTrialDays > 0) {
                    expiresAt = new Date(Date.now() + sTrialDays * 86400000).toISOString();
                }

                db.run('INSERT INTO devices (hwid, label, status, expires_at, app_source) VALUES (?, ?, ?, ?, ?)', [hwid, 'Nouveau Client', status, expiresAt, source], (err) => {
                    if (err) return res.status(500).json({ status: 'error', message: 'Registration failed' });
                    db.run('INSERT INTO ip_history (hwid, ip) VALUES (?, ?)', [hwid, ip]);
                    const msg = status === 'allowed' ? 'Welcome!' : 'Appareil enregistré. Attente d\'approbation.';
                    return res.json({ status, message: msg, expiresAt });
                });
            }
        });
    });
});

// -- STORE & ORDERS API --
app.post('/api/store/order', (req, res) => {
    const { hwid, method, proof } = req.body;
    if (!hwid || !method || !proof) return res.status(400).json({ error: 'Missing fields' });

    db.run('INSERT INTO orders (hwid, method, proof) VALUES (?, ?, ?)', [hwid, method, proof], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        
        // Envoi de la notification Push
        const postData = Buffer.from(`Telegram: ${hwid}\nMéthode: ${method}\nPreuve: ${proof}`, 'utf8');
        const options = {
            hostname: 'ntfy.sh',
            port: 443,
            path: '/Gravity_FUSION_Boutique_Privee_X9V2',
            method: 'POST',
            headers: {
                'Title': 'Nouveau Paiement FUSION',
                'Tags': 'money_with_wings,bell',
                'Priority': 'high',
                'Content-Type': 'text/plain; charset=utf-8',
                'Content-Length': postData.length
            }
        };

        const reqNtfy = https.request(options, (resNtfy) => {
            resNtfy.on('data', () => {}); // Consume data to free memory
        });
        reqNtfy.on('error', (e) => console.error('[Ntfy Error]', e));
        reqNtfy.write(postData);
        reqNtfy.end();

        res.json({ success: true, message: 'Commande reçue. En attente de validation.' });
    });
});

app.get('/api/store/status', (req, res) => {
    const { hwid } = req.query;
    if (!hwid) return res.status(400).json({ error: 'Missing HWID' });

    db.get('SELECT * FROM orders WHERE hwid = ? ORDER BY created_at DESC LIMIT 1', [hwid], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.json({ status: 'none' });
        
        let downloadLink = null;
        if (row.status === 'approved') {
            downloadLink = 'https://mega.nz/file/T1hg3aBA#Ny_o8pxNj1sKtKpAsW1m8gDWpOFblyr4vFmdHrMISKQ';
        }
        res.json({ status: row.status, method: row.method, downloadLink });
    });
});

// -- ADMIN APIS --
app.get('/api/admin/stats', authMiddleware, (req, res) => {
    db.all('SELECT status, expires_at, app_source, approved_by FROM devices', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        
        let filteredRows = rows;
        if (req.adminName === 'Brodie') {
            filteredRows = rows.filter(r => r.app_source !== 'FUSION' && r.approved_by !== 'Gravity');
        }

        let total = filteredRows.length;
        let active = 0;
        let pending = 0;
        let banned = 0;

        filteredRows.forEach(r => {
            if (r.status === 'banned') banned++;
            else if (r.status === 'pending') pending++;
            else if (r.status === 'allowed') {
                if (r.expires_at && new Date(r.expires_at) < new Date()) {
                    // expired
                } else {
                    active++;
                }
            }
        });

        db.get('SELECT COUNT(*) as pendingOrders FROM orders WHERE status = "pending"', [], (err, orderRow) => {
            res.json({ total, active, pending, banned, pendingOrders: orderRow ? orderRow.pendingOrders : 0 });
        });
    });
});

app.get('/api/admin/devices', authMiddleware, (req, res) => {
    db.all('SELECT * FROM devices ORDER BY last_seen DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        
        let filteredRows = rows;
        if (req.adminName === 'Brodie') {
            filteredRows = rows.filter(r => r.app_source !== 'FUSION' && r.approved_by !== 'Gravity');
        }

        const safeRows = filteredRows.map(r => {
            if (r.hwid === ADMIN_HWID) {
                return { ...r, last_ip: 'Cachée (Admin)' };
            }
            return r;
        });
        res.json(safeRows);
    });
});

app.get('/api/admin/device-details', authMiddleware, (req, res) => {
    const { hwid } = req.query;
    db.get('SELECT * FROM devices WHERE hwid = ?', [hwid], (err, dev) => {
        if (err || !dev) return res.status(404).json({ error: 'Device not found' });
        
        if (hwid === ADMIN_HWID) {
            return res.json({
                ...dev,
                last_ip: 'Cachée (Admin)',
                ips: [{ ip: 'Cachée (Admin)', at: new Date().toISOString() }]
            });
        }

        db.all('SELECT ip, at FROM ip_history WHERE hwid = ? ORDER BY at DESC LIMIT 10', [hwid], (err, ips) => {
            res.json({
                ...dev,
                ips: ips || []
            });
        });
    });
});

app.post('/api/admin/save', authMiddleware, (req, res) => {
    const { hwid, label, note, expiresAt, status } = req.body;
    if (hwid === ADMIN_HWID) {
        return res.status(403).json({ error: 'Cannot modify Admin device' });
    }
    const expVal = expiresAt ? new Date(expiresAt).toISOString() : null;

    db.run(
        'UPDATE devices SET label = ?, note = ?, expires_at = ?, status = ?, approved_by = ? WHERE hwid = ?',
        [label, note, expVal, status, req.adminName, hwid],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

app.post('/api/admin/delete', authMiddleware, (req, res) => {
    const { hwid } = req.body;
    if (hwid === ADMIN_HWID) {
        return res.status(403).json({ error: 'Cannot delete Admin device' });
    }
    db.run('DELETE FROM devices WHERE hwid = ?', [hwid], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        db.run('DELETE FROM ip_history WHERE hwid = ?', [hwid]);
        res.json({ success: true });
    });
});

app.get('/api/admin/orders', authMiddleware, (req, res) => {
    db.all('SELECT * FROM orders ORDER BY created_at DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/admin/orders/action', authMiddleware, (req, res) => {
    const { id, action } = req.body; // action: 'approve' or 'reject'
    if (action === 'approve') {
        db.run('UPDATE orders SET status = "approved" WHERE id = ?', [id], () => {
            res.json({ success: true });
        });
    } else {
        db.run('UPDATE orders SET status = "rejected" WHERE id = ?', [id], () => {
            res.json({ success: true });
        });
    }
});

app.get('/api/admin/settings', authMiddleware, (req, res) => {
    getSettings((err, settings) => {
        if (err) return res.status(500).json({ error: err.message });
        if (req.adminName === 'Gravity') {
            res.json({
                allowRegistration: settings.fusion_allowRegistration,
                autoApprove: settings.fusion_autoApprove,
                trialDays: settings.fusion_trialDays
            });
        } else {
            res.json({
                allowRegistration: settings.allowRegistration,
                autoApprove: settings.autoApprove,
                trialDays: settings.trialDays
            });
        }
    });
});

app.post('/api/admin/settings', authMiddleware, (req, res) => {
    const { allowRegistration, autoApprove, trialDays } = req.body;
    
    const prefix = req.adminName === 'Gravity' ? 'fusion_' : '';

    db.serialize(() => {
        const stmt = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
        stmt.run(`${prefix}allowRegistration`, String(allowRegistration === true || allowRegistration === 'true'));
        stmt.run(`${prefix}autoApprove`, String(autoApprove === true || autoApprove === 'true'));
        stmt.run(`${prefix}trialDays`, String(parseInt(trialDays, 10) || 0));
        stmt.finalize((err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
    });
});

app.listen(PORT, () => {
    console.log(`[Gravity HWID] Server running on port ${PORT}`);
    console.log(`[Gravity HWID] Dashboard: http://localhost:${PORT}`);
});
