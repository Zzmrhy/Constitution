const jwt = require('jsonwebtoken');
const fs = require('fs');

const JWT_SECRET = 'dev-secret-change-me';

try {
    const tokens = JSON.parse(fs.readFileSync('./API/refreshTokens.json', 'utf8'));
    const vincentTokens = [];
    tokens.forEach((token, index) => {
        try {
            const payload = jwt.verify(token, JWT_SECRET);
            if (payload.username === 'Vincent Kuhl') {
                vincentTokens.push({ index, token, payload });
            }
        } catch (err) {
            console.log(`Invalid token at index ${index}:`, err.message);
        }
    });
    console.log('Tokens for Vincent Kuhl:', vincentTokens);
} catch (err) {
    console.error('Error:', err);
}
