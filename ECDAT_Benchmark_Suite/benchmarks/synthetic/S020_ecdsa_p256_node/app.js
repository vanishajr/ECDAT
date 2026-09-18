const crypto=require('crypto');
const ecdh=crypto.createECDH('prime256v1');
ecdh.generateKeys();
