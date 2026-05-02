package main

import (
	"bytes"
	"fmt"
	"testing"
)

func TestGetBlockSize(t *testing.T) {
	type testCase struct {
		keyLen     int
		cipherType int
		expected   int
		shouldFail bool
	}

	runCases := []testCase{
		{64, typeAES, 0, true}, // Invalid AES key length
		{8, typeDES, 8, false}, // Valid DES key length
		{16, typeDES, 0, true}, // Invalid DES key length
		{1, -1, 0, true},       // Invalid cipher type
	}

	submitCases := append(runCases, []testCase{
		{16, typeAES, 16, false}, // Valid AES key length
		{24, typeAES, 16, false}, // Valid AES key length
		{32, typeAES, 16, false}, // Valid AES key length
	}...)

	testCases := runCases
	if withSubmit {
		testCases = submitCases
	}

	skipped := len(submitCases) - len(testCases)

	passCount := 0
	failCount := 0

	for _, test := range testCases {
		blockSize, err := getBlockSize(test.keyLen, test.cipherType)
		if (err != nil) != test.shouldFail {
			failCount++
			t.Errorf(`---------------------------------
Inputs:      keyLen: %v, cipherType: %v
Expecting:   Error: %v
Actual:      Error: %v
Fail
`, test.keyLen, test.cipherType, test.shouldFail, err != nil)
		} else if blockSize != test.expected && !test.shouldFail {
			failCount++
			t.Errorf(`---------------------------------
Inputs:      keyLen: %v, cipherType: %v
Expecting:   Block Size: %v
Actual:      Block Size: %v
Fail
`, test.keyLen, test.cipherType, test.expected, blockSize)
		} else {
			passCount++
			fmt.Printf(`---------------------------------
Inputs:      keyLen: %v, cipherType: %v
Expecting:   Block Size: %v
Actual:      Block Size: %v
Pass
`, test.keyLen, test.cipherType, test.expected, blockSize)
		}
	}

	fmt.Println("---------------------------------")
	if skipped > 0 {
		fmt.Printf("%d passed, %d failed, %d skipped\n", passCount, failCount, skipped)
	} else {
		fmt.Printf("%d passed, %d failed\n", passCount, failCount)
	}

}
func TestPadWithZeros(t *testing.T) {
	type testCase struct {
		input       []byte
		desiredSize int
		expected    []byte
	}

	runCases := []testCase{
		{[]byte{0xFF}, 4, []byte{0xFF, 0x00, 0x00, 0x00}},
		{[]byte{0xFA, 0xBC}, 8, []byte{0xFA, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{[]byte{0x12, 0x34, 0x56}, 12, []byte{0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	submitCases := append(runCases, []testCase{
		{[]byte{0xFA}, 16, []byte{0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{[]byte{}, 10, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}...)

	testCases := runCases
	if withSubmit {
		testCases = submitCases
	}
	skipped := len(submitCases) - len(testCases)

	passed, failed := 0, 0

	for _, test := range testCases {
		result := padWithZeros(test.input, test.desiredSize)
		if !bytes.Equal(result, test.expected) {
			t.Errorf(`---------------------------------
Input:     %v
Expecting: %v
Actual:    %v
Fail
`, test.input, test.expected, result)
			failed++
		} else {
			fmt.Printf(`---------------------------------
Input:     %v
Expecting: %v
Actual:    %v
Pass
`, test.input, test.expected, result)
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

func TestDeriveRoundKey(t *testing.T) {
	type testCase struct {
		masterKey   [4]byte
		roundNumber int
		expected    [4]byte
	}

	runCases := []testCase{
		{[4]byte{0xAA, 0xFF, 0x11, 0xBC}, 1, [4]byte{0xAB, 0xFE, 0x10, 0xBD}},
		{[4]byte{0xEB, 0xCD, 0x13, 0xFC}, 2, [4]byte{0xE9, 0xCF, 0x11, 0xFE}},
	}

	submitCases := append(runCases, []testCase{
		{[4]byte{0xAA, 0xFF, 0x11, 0xBC}, 5, [4]byte{0xAF, 0xFA, 0x14, 0xB9}},
		{[4]byte{0xEB, 0xCD, 0x13, 0xFC}, 7, [4]byte{0xEC, 0xCA, 0x14, 0xFB}},
	}...)

	testCases := runCases
	if withSubmit {
		testCases = submitCases
	}

	skipped := len(submitCases) - len(testCases)
	passed, failed := 0, 0

	for _, test := range testCases {
		result := deriveRoundKey(test.masterKey, test.roundNumber)
		if result != test.expected {
			failed++
			t.Errorf(`---------------------------------
Inputs:    masterKey: %X, roundNumber: %d
Expecting: roundKey: %X
Actual:    roundKey: %X
Fail
`, test.masterKey, test.roundNumber, test.expected, result)
		} else {
			passed++
			fmt.Printf(`---------------------------------
Inputs:    masterKey: %X, roundNumber: %d
Expecting: roundKey: %X
Actual:    roundKey: %X
Pass
`, test.masterKey, test.roundNumber, test.expected, result)
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
