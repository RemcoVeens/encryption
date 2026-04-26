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
		{"Shazam", "Sk7p13"},
		{"I'm lovin it", "mysecurepass"},
	}

	submitCases := append(runCases, []testCase{
		{"Don't tell him I'm in love", "c5f149783abf22a96e9a7bb999"},
	}...)

	testCases := runCases
	if withSubmit {
		testCases = submitCases
	}

	skipped := len(submitCases) - len(testCases)

	passCount := 0
	failCount := 0

	for _, test := range testCases {
		ciphertext := encrypt([]byte(test.plaintext), []byte(test.key))
		if string(ciphertext) == test.plaintext {
			failCount++
			t.Errorf(`---------------------------------
Inputs:      plaintext: %s, key: %s
Expecting:   ciphertext to differ from plaintext
Actual:      ciphertext matches plaintext (encryption not applied)
Fail
`, test.plaintext, test.key)
			continue
		}
		decrypted := decrypt(ciphertext, []byte(test.key))
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
