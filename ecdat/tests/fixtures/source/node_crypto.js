const crypto = require('crypto');

function encrypt(key, iv, data) {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}

function sha256(data) {
    return crypto.createHash('sha256').update(data).digest();
}

function ecdh() {
    return crypto.createECDH('prime256v1');
}
