package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math"
)

func padPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func encryptAES(key, plaintext []byte) ([]byte, []byte, error) {

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, nil, fmt.Errorf("invalid key size: must be 16, 24, or 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// GENERATE AN IV a random vector
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	plaintext = padPKCS7(plaintext, aes.BlockSize)

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, iv, nil
}

func calculateEntropy(data []byte) float64 {
	var entropy float64
	for _, char := range data {
		frequency := float64(char) / float64(len(data))
		entropy -= frequency * math.Log2(frequency)
	}
	return entropy
}

func main() {
	key := []byte("examplekey123456") // 16 bytes
	plaintext := []byte("Secret message!")

	ciphertext, iv, err := encryptAES(key, plaintext)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	entropy := calculateEntropy(ciphertext)
	fmt.Printf("Entropy: %.2f bits\n", entropy)
	fmt.Printf("Ciphertext (hex): %s\n", hex.EncodeToString(ciphertext))
	fmt.Printf("IV (hex): %s\n", hex.EncodeToString(iv))
}
