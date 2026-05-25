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

function download() {
    const options = {
        hostname: 'api.github.com',
        path: `/gists/${GIST_ID}`,
        headers: { 'Authorization': `token ${TOKEN}`, 'User-Agent': 'Node.js' }
    };
    https.get(options, res => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => {
            if (res.statusCode === 200) {
                const gist = JSON.parse(data);
                if (gist.files && gist.files['database.b64'] && gist.files['database.b64'].content !== 'init') {
                    const b64 = gist.files['database.b64'].content;
                    fs.writeFileSync(DB_PATH, Buffer.from(b64, 'base64'));
                    console.log('[DB-SYNC] Base de données restaurée depuis GitHub.');
                }
            } else {
                console.error('[DB-SYNC] Erreur de téléchargement du Gist:', res.statusCode);
            }
        });
    }).on('error', err => console.error(err));
}

download();
