package crypto-utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
)

/*
 * AES key.
 */
const keySTR = "LJV8J0m*J.TbgfqE"

/*
 * Encrypt plantext with AES algorithm.
 * Return encrypted hex string.
 */
func Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher([]byte(keySTR))
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

/*
 * Decrypt hex string with AES algorithm.
 * Return decrypted plantext.
 */
func Decrypt(ciphertext string) (string, error) {
	cipheSlice, err := hex.DecodeString(ciphertext)

	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(keySTR))
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	nonce, cipheSlice := cipheSlice[:nonceSize], cipheSlice[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, cipheSlice, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
