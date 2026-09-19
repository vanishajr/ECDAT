use aes_gcm::{Aes256Gcm, KeyInit};
use sha2::{Digest, Sha256};

pub fn seal(key: &[u8], nonce: &[u8], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    cipher.encrypt(nonce.into(), data).unwrap().to_vec()
}

pub fn digest(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}
