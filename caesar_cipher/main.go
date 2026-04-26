package caesar_cipher

import (
	"bytes"
	"encoding/binary"
)

func encrypt(plaintext string, key int) string {
	return crypt(plaintext, key)
}

func decrypt(ciphertext string, key int) string {
	return crypt(ciphertext, -key)
}

// Helper function: intToBytes converts an integer to a 3-byte slice (little-endian)
func intToBytes(num int) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, int64(num))
	if err != nil {
		return nil
	}
	bs := buf.Bytes()
	if len(bs) > 3 {
		return bs[:3]
	}
	return bs
}

func crypt(text string, key int) string {
	res := ""
	for _, c := range text {
		res += getOffsetChar(c, key)
	}
	return res
}
func getOffsetChar(c rune, offset int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	pindas := 0
	for i, ch := range alphabet {
		if c == ch {
			pindas = i
			break
		}
	}
	wrapped_index := (pindas + offset) % len(alphabet)
	if offset < 0 {
		wrapped_index = (wrapped_index + len(alphabet)) % len(alphabet)
	}
	char := alphabet[wrapped_index]

	return string(char)
}
