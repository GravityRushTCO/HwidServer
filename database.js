const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { execSync, exec } = require('child_process');

// Sur Railway/cloud, utiliser /tmp ou la variable d'environnement DB_PATH
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.sqlite');

console.log(`[DB] Chemin base de données: ${DB_PATH}`);

try {
    console.log('[DB-SYNC] Vérification de sauvegarde distante...');
    execSync('node sync_down.js', { stdio: 'inherit', cwd: __dirname });
} catch (e) {
    console.log('[DB-SYNC] Échec ou première initialisation.');
}

const db = new sqlite3.Database(DB_PATH);

// Sauvegarde toutes les 30 secondes
setInterval(() => {
    exec('node sync_up.js', { cwd: __dirname }, (error, stdout, stderr) => {
        if (stdout) console.log(stdout.trim());
        if (stderr) console.error(stderr.trim());
    });
}, 30 * 1000);

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hwid TEXT UNIQUE,
        label TEXT,
        note TEXT,
        status TEXT DEFAULT 'pending',
        expires_at DATETIME,
        last_ip TEXT,
        last_country TEXT,
        app_source TEXT DEFAULT 'Unknown',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Commandes (Boutique)
    db.run(`CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hwid TEXT,
        method TEXT,
        proof TEXT,
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS ip_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hwid TEXT,
        ip TEXT,
        country TEXT,
        at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )`);

    // Add approved_by column if it doesn't exist
    db.run(`ALTER TABLE devices ADD COLUMN approved_by TEXT`, (err) => {
        if (!err) console.log('[DB] Colonne approved_by ajoutée.');
    });

    // Add app_source column if it doesn't exist
    db.run(`ALTER TABLE devices ADD COLUMN app_source TEXT DEFAULT 'Unknown'`, (err) => {
        if (!err) console.log('[DB] Colonne app_source ajoutée.');
    });
});

module.exports = db;
