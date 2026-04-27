package main

import (
	"fmt"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	type testCase struct {
		plaintext string
		key       string
	}

	runCases := []testCase{
		{"Shazam", "Sk7p13"},             // Key length matches plaintext length
		{"I'm lovin it", "mysecurepass"}, // Key length matches plaintext length
	}

	submitCases := append(runCases, []testCase{
		{"Kaladin", "Radiant"},           // Updated key length matches plaintext
		{"Another test", "shorttestkey"}, // Updated key length matches plaintext
	}...)

	testCases := runCases
	if withSubmit {
		testCases = submitCases
	}

	skipped := len(submitCases) - len(testCases)

	passCount := 0
	failCount := 0

	for _, test := range testCases {
		fmt.Printf("Encrypting plaintext: '%s' with key: '%s'\n", test.plaintext, test.key)

		ciphertext, err := encrypt([]byte(test.plaintext), []byte(test.key))
		if err != nil {
			t.Errorf("Error during encryption: %v", err)
			failCount++
			continue
		}

		fmt.Printf("Encrypted ciphertext bytes: %v\n", ciphertext)

		decrypted, err := decrypt(ciphertext, []byte(test.key))
		if err != nil {
			t.Errorf("Error during decryption: %v", err)
			failCount++
			continue
		}

		if string(decrypted) != test.plaintext {
			failCount++
			t.Errorf(`---------------------------------
Inputs:      plaintext: %s, key: %s
Expecting:   decrypted: %s
Actual:      decrypted: %s
Fail
`, test.plaintext, test.key, test.plaintext, string(decrypted))
		} else {
			passCount++
			fmt.Printf(`---------------------------------
Inputs:      plaintext: %s, key: %s
Expecting:   decrypted: %s
Actual:      decrypted: %s
Pass
`, test.plaintext, test.key, test.plaintext, string(decrypted))
		}
	}

	fmt.Println("---------------------------------")
	if skipped > 0 {
		fmt.Printf("%d passed, %d failed, %d skipped\n", passCount, failCount, skipped)
	} else {
		fmt.Printf("%d passed, %d failed\n", passCount, failCount)
	}
}

// withSubmit is set at compile time depending
// on which button is used to run the tests
var withSubmit = true
