const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin_gravity';

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
    if (authHeader === ADMIN_PASSWORD) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

// -- CLIENT HANDSHAKE API --
app.get('/api/auth', (req, res) => {
    const hwid = req.query.hwid;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!hwid) {
        return res.status(400).send('error');
    }

    db.get('SELECT * FROM devices WHERE hwid = ?', [hwid], (err, row) => {
        if (err) {
            return res.status(500).send('error');
        }

        if (row) {
            // Update last seen & IP
            db.run('UPDATE devices SET last_seen = CURRENT_TIMESTAMP, last_ip = ? WHERE hwid = ?', [ip, hwid]);
            db.run('INSERT INTO ip_history (hwid, ip) VALUES (?, ?)', [hwid, ip]);

            if (row.status === 'banned') {
                return res.send('banned');
            }

            if (row.expires_at) {
                const expiry = new Date(row.expires_at).getTime();
                if (Date.now() > expiry) {
                    return res.send('expired');
                }
            }

            return res.send('allowed');
        } else {
            // Self-register as pending
            db.run('INSERT INTO devices (hwid, label, status) VALUES (?, ?, ?)', [hwid, 'Nouveau Client', 'pending'], (err) => {
                if (err) return res.status(500).send('error');
                db.run('INSERT INTO ip_history (hwid, ip) VALUES (?, ?)', [hwid, ip]);
                return res.send('pending');
            });
        }
    });
});

app.post('/api/auth', (req, res) => {
    const { hwid } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!hwid) {
        return res.status(400).json({ status: 'error', message: 'HWID is required' });
    }

    db.get('SELECT * FROM devices WHERE hwid = ?', [hwid], (err, row) => {
        if (err) {
            return res.status(500).json({ status: 'error', message: 'Database error' });
        }

        if (row) {
            // Update last seen & IP
            db.run('UPDATE devices SET last_seen = CURRENT_TIMESTAMP, last_ip = ? WHERE hwid = ?', [ip, hwid]);
            db.run('INSERT INTO ip_history (hwid, ip) VALUES (?, ?)', [hwid, ip]);

            if (row.status === 'banned') {
                return res.json({ status: 'banned', message: 'Votre appareil est banni de ce mod menu.' });
            }

            if (row.expires_at) {
                const expiry = new Date(row.expires_at).getTime();
                if (Date.now() > expiry) {
                    return res.json({ status: 'expired', message: 'Votre licence a expiré. Veuillez la renouveler.' });
                }
            }

            return res.json({ status: 'allowed', message: 'Welcome!', expiresAt: row.expires_at || null });
        } else {
            // Self-register as pending
            db.run('INSERT INTO devices (hwid, label, status) VALUES (?, ?, ?)', [hwid, 'Nouveau Client', 'pending'], (err) => {
                if (err) return res.status(500).json({ status: 'error', message: 'Registration failed' });
                db.run('INSERT INTO ip_history (hwid, ip) VALUES (?, ?)', [hwid, ip]);
                return res.json({ status: 'pending', message: 'Appareil enregistré. Attente d\'approbation.' });
            });
        }
    });
});

// -- ADMIN APIS --
app.get('/api/admin/stats', authMiddleware, (req, res) => {
    db.all('SELECT status, expires_at FROM devices', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        
        let total = rows.length;
        let active = 0;
        let pending = 0;
        let banned = 0;

        rows.forEach(r => {
            if (r.status === 'banned') banned++;
            else if (r.status === 'pending') pending++;
            else if (r.status === 'allowed') {
                if (r.expires_at && Date.now() > new Date(r.expires_at).getTime()) {
                    banned++; // Treat expired as banned/inactive
                } else {
                    active++;
                }
            }
        });

        res.json({ total, active, pending, banned });
    });
});

app.get('/api/admin/devices', authMiddleware, (req, res) => {
    db.all('SELECT * FROM devices ORDER BY last_seen DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/admin/device-details', authMiddleware, (req, res) => {
    const { hwid } = req.query;
    db.get('SELECT * FROM devices WHERE hwid = ?', [hwid], (err, dev) => {
        if (err || !dev) return res.status(404).json({ error: 'Device not found' });
        
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
    const expVal = expiresAt ? new Date(expiresAt).toISOString() : null;

    db.run(
        'UPDATE devices SET label = ?, note = ?, expires_at = ?, status = ? WHERE hwid = ?',
        [label, note, expVal, status, hwid],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

app.post('/api/admin/delete', authMiddleware, (req, res) => {
    const { hwid } = req.body;
    db.run('DELETE FROM devices WHERE hwid = ?', [hwid], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        db.run('DELETE FROM ip_history WHERE hwid = ?', [hwid]);
        res.json({ success: true });
    });
});

app.listen(PORT, () => {
    console.log(`[Gravity HWID] Server running on port ${PORT}`);
    console.log(`[Gravity HWID] Admin password: ${ADMIN_PASSWORD}`);
    console.log(`[Gravity HWID] Dashboard: http://localhost:${PORT}`);
});
