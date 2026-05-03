package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"testing"
)

func TestFeistel(t *testing.T) {
	type testCase struct {
		msg      []byte
		key      []byte
		rounds   int
		expected string
	}

	runCases := []testCase{
		{[]byte("General Kenobi!!!!"), []byte("thesecret"), 8, "General Kenobi!!!!"},
		{[]byte("Hello there!"), []byte("@n@kiN"), 16, "Hello there!"},
	}

	submitCases := append(runCases, []testCase{
		{[]byte("Goodbye!"), []byte("roundkey"), 8, "Goodbye!"},
	}...)

	testCases := runCases
	if withSubmit {
		testCases = submitCases
	}
	skipped := len(submitCases) - len(testCases)

	passed, failed := 0, 0

	for _, test := range testCases {
		roundKeys := generateRoundKeys(test.key, test.rounds)
		encrypted := feistel(test.msg, roundKeys)
		decrypted := feistel(encrypted, reverse(roundKeys))

		if string(encrypted) == string(test.msg) {
			failed++
			t.Errorf(`---------------------------------
Inputs:      msg: %v, key: %v, rounds: %d
Expecting:   encrypted message to differ from original
Actual:      encrypted message is identical to original (encryption did not occur)
Fail
`, test.msg, test.key, test.rounds)
			continue
		}

		if string(decrypted) != test.expected {
			failed++
			t.Errorf(`---------------------------------
Inputs:      msg: %v, key: %v, rounds: %d
Expecting:   decrypted: %s
Actual:      decrypted: %s
Fail
`, test.msg, test.key, test.rounds, test.expected, string(decrypted))
		} else {
			passed++
			fmt.Printf(`---------------------------------
Inputs:      msg: %v, key: %v, rounds: %d
Expecting:   decrypted: %s
Actual:      decrypted: %s
Pass
`, test.msg, test.key, test.rounds, test.expected, string(decrypted))
		}
	}

	fmt.Println("---------------------------------")
	if skipped > 0 {
		fmt.Printf("%d passed, %d failed, %d skipped\n", passed, failed, skipped)
	} else {
		fmt.Printf("%d passed, %d failed\n", passed, failed)
	}

}

func generateRoundKeys(key []byte, rounds int) [][]byte {
	roundKeys := [][]byte{}
	for i := 0; i < rounds; i++ {
		ui := binary.BigEndian.Uint32(key)
		rotated := bits.RotateLeft32(uint32(ui), i)
		finalRound := make([]byte, len(key))
		binary.LittleEndian.PutUint32(finalRound, uint32(rotated))
		roundKeys = append(roundKeys, finalRound)
	}
	return roundKeys
}

func TestEncryptDecrypt(t *testing.T) {
	type testCase struct {
		key       []byte
		plaintext []byte
		expected  string
	}

	runCases := []testCase{
		{[]byte("12344321"), []byte("Today I met my crush, what a hunk"), "Today I met my crush, what a hunk"},
		{[]byte("p@$$w0rd"), []byte("I hope my boyfriend never finds out about this"), "I hope my boyfriend never finds out about this"},
		{[]byte("secretky"), []byte("The best secret ever!"), "The best secret ever!"},
		{[]byte("longpass"), []byte("Just testing DES encryption with padding"), "Just testing DES encryption with padding"},
	}

	submitCases := append(runCases, []testCase{
		{[]byte("secretky"), []byte("The best secret ever!"), "The best secret ever!"},
		{[]byte("longpass"), []byte("Just testing DES encryption with padding"), "Just testing DES encryption with padding"},
	}...)

	testCases := runCases
	if withSubmit {
		testCases = submitCases
	}
	skipped := len(submitCases) - len(testCases)

	passed, failed := 0, 0

	for _, test := range testCases {
		ciphertext, err := encrypt(test.key, test.plaintext)
		if err != nil {
			t.Errorf(`---------------------------------
Encryption failed for key: %v
plaintext: %v
error: %v
Fail
`, string(test.key), string(test.plaintext), err)
			failed++
			continue
		}

		decryptedText, err := decrypt(test.key, ciphertext)
		if err != nil {
			t.Errorf(`---------------------------------
Decryption failed for key: %v
ciphertext: %v
error: %v
Fail
`, string(test.key), ciphertext, err)
			failed++
			continue
		}
		decryptedText = bytes.Trim(decryptedText, "\x00")

		if string(decryptedText) != test.expected {
			t.Errorf(`---------------------------------
Inputs:      key: %v, plaintext: %v
Expecting:   decrypted: %v
Actual:      decrypted: %v
Fail
`, string(test.key), string(test.plaintext), test.expected, string(decryptedText))
			failed++
		} else {
			fmt.Printf(`---------------------------------
Inputs:      key: %v, plaintext: %v
Expecting:   decrypted: %v
Actual:      decrypted: %v
Pass
`, string(test.key), string(test.plaintext), test.expected, string(decryptedText))
			passed++
		}
	}

	fmt.Println("---------------------------------")
	if skipped > 0 {
		fmt.Printf("%d passed, %d failed, %d skipped\n", passed, failed, skipped)
	} else {
		fmt.Printf("%d passed, %d failed\n", passed, failed)
	}

}

func TestGenerateIV(t *testing.T) {
	type testCase struct {
		length   int
		expected int
	}

	runCases := []testCase{
		{8, 8},
		{10, 10},
		{16, 16},
	}

	submitCases := append(runCases, []testCase{
		{12, 12},
		{14, 14},
	}...)

	testCases := runCases
	if withSubmit {
		testCases = submitCases
	}

	skipped := len(submitCases) - len(testCases)
	passed, failed := 0, 0

	for _, test := range testCases {
		iv, err := generateIV(test.length)
		if err != nil {
			t.Errorf("Failed to generate IV for length %d: %v", test.length, err)
			failed++
			continue
		}

		if len(iv) != test.expected {
			t.Errorf(`---------------------------------
Inputs:      length: %d
Expecting:   IV length: %d
Actual:      IV length: %d
Fail
`, test.length, test.expected, len(iv))
			failed++
		} else {
			fmt.Printf(`---------------------------------
Inputs:      length: %d
Expecting:   IV length: %d
Actual:      IV length: %d
Pass
`, test.length, test.expected, len(iv))
			passed++
		}
	}

	fmt.Println("---------------------------------")
	if skipped > 0 {
		fmt.Printf("%d passed, %d failed, %d skipped\n", passed, failed, skipped)
	} else {
		fmt.Printf("%d passed, %d failed\n", passed, failed)
	}

}

// withSubmit is set at compile time depending
// on which button is used to run the tests
var withSubmit = true
