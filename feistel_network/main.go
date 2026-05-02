package main

import (
	"crypto/sha256"
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
