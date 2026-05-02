package main

import (
	"crypto/aes"
	"crypto/des"
	"fmt"
)

const (
	typeAES = iota
	typeDES
)

func getCipherTypeName(cipherType int) string {
	switch cipherType {
	case typeAES:
		return "AES"
	case typeDES:
		return "DES"
	}
	return "unknown"
}

func test(keyLen, cipherType int) {
	fmt.Printf(
		"Getting block size of %v cipher with key length %v...\n",
		getCipherTypeName(cipherType),
		keyLen,
	)
	blockSize, err := getBlockSize(keyLen, cipherType)
	if err != nil {
		fmt.Println(err)
		fmt.Println("========")
		return
	}
	fmt.Println("Block size:", blockSize)
	fmt.Println("========")
}

func getBlockSize(keyLen, cipherType int) (int, error) {
	typeciher := getCipherTypeName(cipherType)
	fakeKey := make([]byte, keyLen)

	switch typeciher {
	case "AES":
		chipher, err := aes.NewCipher(fakeKey)
		if err != nil {
			return 0, err
		}
		return chipher.BlockSize(), nil
	case "DES":
		chipher, err := des.NewCipher(fakeKey)
		if err != nil {
			return 0, err
		}
		return chipher.BlockSize(), nil
	default:
		return 0, fmt.Errorf("invalid cipher type")
	}
}

func padWithZeros(block []byte, desiredSize int) []byte {
	if len(block) < desiredSize {
		block = append(block, make([]byte, (desiredSize-len(block)))...)
	}
	return block
}

func deriveRoundKey(masterKey [4]byte, roundNumber int) [4]byte {
	roundKey := [4]byte{}
	for i := range roundKey {
		roundKey[i] = masterKey[i] ^ byte(roundNumber)
	}
	return roundKey
}
