package xor

func crypt(plaintext, key []byte) []byte {
	res := make([]byte, len(plaintext))
	for i, c := range plaintext {
		res[i] = c ^ key[i%len(key)]
	}
	return res
}

// encrypt function uses the crypt function for XOR encryption
func encrypt(plaintext, key []byte) []byte {
	return crypt(plaintext, key)
}

// decrypt function uses the crypt function for XOR decryption
func decrypt(ciphertext, key []byte) []byte {
	return crypt(ciphertext, key)
}
