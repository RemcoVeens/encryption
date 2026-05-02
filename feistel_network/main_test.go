package main

import (
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

// withSubmit is set at compile time depending
// on which button is used to run the tests
var withSubmit = true
