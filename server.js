const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 8080;

let db = new sqlite3.Database('totally_not_my_privateKeys.db');

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;

async function generateKeyPairs() {
    keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
    expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });

    db.run(`CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        exp INTEGER NOT NULL
    )`);

    db.run(`INSERT INTO keys (key, exp) VALUES (?, ?)`, [JSON.stringify(keyPair), Math.floor(Date.now() / 1000) + 3600]);
    db.run(`INSERT INTO keys (key, exp) VALUES (?, ?)`, [JSON.stringify(expiredKeyPair), Math.floor(Date.now() / 1000) - 3600]);
}

async function generateToken() {
    const payload = {
        user: 'sampleUser',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600
    };
    const options = {
        algorithm: 'RS256',
        header: {
            typ: 'JWT',
            alg: 'RS256',
            kid: keyPair.kid
        }
    };
    token = jwt.sign(payload, keyPair.toPEM(true), options);
}

async function generateExpiredJWT() {
    const payload = {
        user: 'sampleUser',
        iat: Math.floor(Date.now() / 1000) - 30000,
        exp: Math.floor(Date.now() / 1000) - 3600
    };
    const options = {
        algorithm: 'RS256',
        header: {
            typ: 'JWT',
            alg: 'RS256',
            kid: expiredKeyPair.kid
        }
    };
    expiredToken = jwt.sign(payload, expiredKeyPair.toPEM(true), options);
}

app.all('/auth', (req, res, next) => {
    if (req.method !== 'POST') {
        return res.status(405).send('Method Not Allowed');
    }
    next();
});

app.all('/.well-known/jwks.json', (req, res, next) => {
    if (req.method !== 'GET') {
        return res.status(405).send('Method Not Allowed');
    }
    next();
});

app.get('/.well-known/jwks.json', (req, res) => {
    db.all(`SELECT key FROM keys WHERE exp > ?`, [Math.floor(Date.now() / 1000)], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        const validKeysJSON = rows.map(row => JSON.parse(row.key));
        res.setHeader('Content-Type', 'application/json');
        res.json({ keys: validKeysJSON });
    });
});

app.post('/auth', async (req, res) => {
    let tokenToSend;
    if (req.query.expired === 'true') {
        tokenToSend = expiredToken;
    } else {
        tokenToSend = token;
    }
    res.send(tokenToSend);
});

generateKeyPairs().then(() => {
    generateToken();
    generateExpiredJWT();
    app.listen(port, () => {
        console.log(`Server started on http://localhost:${port}`);
    });
});
