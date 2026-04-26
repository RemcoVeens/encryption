package brute_force

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"strings"
)

func generateRandomKey(length int) (string, error) {
	randReader := rand.New(rand.NewSource(0))
	key := make([]byte, length)
	_, err := randReader.Read(key)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", key), nil
}

func base8Char(bits byte) string {
	const base8Alphabet = "ABCDEFGH"
	it := int(bits)
	if it >= len(base8Alphabet) {
		return ""
	}
	return string(base8Alphabet[it])
}

func main() {
	alphabetSize(4)
}

func getHexBytes(s string) ([]byte, error) {
	// example input: 48:65:6c:6c:6f
	return hex.DecodeString(strings.Join(strings.Split(s, ":"), ""))
}

func alphabetSize(numBits int) float64 {
	return math.Pow(2, float64(numBits))
}

func findKey(encrypted []byte, decrypted string) ([]byte, error) {
	for n := range int(math.Pow(2, 24)) {
		key := intToBytes(n)
		res := crypt(encrypted, key)
		fmt.Printf("%d: %s = %s\n", n, res, decrypted)
		if string(res) == decrypted {
			return key, nil
		}
	}
	return nil, fmt.Errorf("key not found")
}

// Helper function: crypt performs XOR-based encryption/decryption
func crypt(dat, key []byte) []byte {
	final := []byte{}
	for i, d := range dat {
		final = append(final, d^key[i])
	}
	return final
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
