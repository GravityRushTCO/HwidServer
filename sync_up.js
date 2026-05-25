const https = require('https');
const fs = require('fs');
const path = require('path');

const GIST_ID = process.env.GIST_ID || '413c6873a736a25d4cf882e5d9585929';
const TOKEN = process.env.GITHUB_TOKEN;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.sqlite');

if (!TOKEN) {
    console.log('[DB-SYNC] Pas de GITHUB_TOKEN - sync désactivé.');
    process.exit(0);
}

function upload() {
    if (!fs.existsSync(DB_PATH)) {
        return console.log('[DB-SYNC] Pas de DB à upload');
    }
    const b64 = fs.readFileSync(DB_PATH).toString('base64');
    
    const body = JSON.stringify({
        files: {
            "database.b64": { content: b64 }
        }
    });

    const options = {
        hostname: 'api.github.com',
        path: `/gists/${GIST_ID}`,
        method: 'PATCH',
        headers: {
            'Authorization': `token ${TOKEN}`,
            'User-Agent': 'Node.js',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body)
        }
    };

    const req = https.request(options, res => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => {
            if (res.statusCode === 200) {
                console.log('[DB-SYNC] Sauvegarde envoyée vers GitHub avec succès.');
            } else {
                console.error('[DB-SYNC] Erreur upload:', res.statusCode);
            }
        });
    });
    req.on('error', err => console.error(err));
    req.write(body);
    req.end();
}

upload();
