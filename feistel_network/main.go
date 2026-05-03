package main

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/sha256"
	"errors"
	"math/rand"
)

func reverse[T any](s []T) []T {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func xor(lhs, rhs []byte) []byte {
	res := []byte{}
	for i := range lhs {
		res = append(res, lhs[i]^rhs[i])
	}
	return res
}

// outputLength should be equal to or less than the length
// of the left half when used in feistel so that the XOR
// has sufficient bytes to operate on
func hash(first, second []byte, outputLength int) []byte {
	h := sha256.New()
	h.Write(append(first, second...))
	return h.Sum(nil)[:outputLength]
}

func feistel(msg []byte, roundKeys [][]byte) []byte {
	lhs, rhs := msg[:len(msg)/2], msg[len(msg)/2:]
	for _, roundKey := range roundKeys {
		oldRHS := rhs
		nextRHS := xor(lhs, hash(rhs, roundKey, len(lhs)))
		lhs = oldRHS
		rhs = nextRHS
	}
	return append(rhs, lhs...)
}

func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < des.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:des.BlockSize]
	ciphertext = ciphertext[des.BlockSize:]
	if len(ciphertext)%des.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	return ciphertext, nil
}

func padWithZeros(block []byte, desiredSize int) []byte {
	for len(block) < desiredSize {
		block = append(block, 0)
	}
	return block
}
func encrypt(key, plaintext []byte) ([]byte, error) {
	cBlock, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext = padMsg(plaintext, des.BlockSize)
	iv := make([]byte, des.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(cBlock, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	return append(iv, ciphertext...), nil
}

func padMsg(plaintext []byte, blockSize int) []byte {
	if len(plaintext)%blockSize == 0 {
		return plaintext
	}
	return padWithZeros(plaintext, (len(plaintext)/blockSize+1)*blockSize)
}

func generateIV(length int) ([]byte, error) {
	iv := make([]byte, length)
	_, err := rand.Read(iv)
	return iv, err
}
