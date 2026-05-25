const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Sur Railway/cloud, utiliser /tmp ou la variable d'environnement DB_PATH
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.sqlite');

console.log(`[DB] Chemin base de données: ${DB_PATH}`);
const db = new sqlite3.Database(DB_PATH);

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
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS ip_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hwid TEXT,
        ip TEXT,
        country TEXT,
        at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

module.exports = db;
