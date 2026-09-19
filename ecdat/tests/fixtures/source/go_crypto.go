package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func seal(key, nonce, data []byte) []byte {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	return gcm.Seal(nil, nonce, data, nil)
}

func genRSA() any {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return key
}

func digest(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
