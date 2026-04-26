package caesar_cipher

import (
	"fmt"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	type testCase struct {
		plaintext string
		key       int
		expected  string
	}

	runCases := []testCase{
		{"abcdefghi", 1, "bcdefghij"},
		{"hello", 5, "mjqqt"},
	}

	submitCases := append(runCases, []testCase{
		{"correcthorsebatterystaple", 16, "sehhusjxehiurqjjuhoijqfbu"},
		{"onetwothreefourfivesixseveneightnineten", 25, "nmdsvnsgqddentqehudrhwrdudmdhfgsmhmdsdm"},
	}...)

	testCases := runCases
	if withSubmit {
		testCases = submitCases
	}

	skipped := len(submitCases) - len(testCases)

	passCount := 0
	failCount := 0

	for _, test := range testCases {
		encrypted := encrypt(test.plaintext, test.key)
		decrypted := decrypt(encrypted, test.key)
		if decrypted != test.plaintext {
			failCount++
			t.Errorf(`---------------------------------
Inputs:      plaintext: %v, key: %v
Expecting:   decrypted: %v
Actual:      decrypted: %v
Fail
`, test.plaintext, test.key, test.plaintext, decrypted)
		} else if encrypted != test.expected {
			failCount++
			t.Errorf(`---------------------------------
Inputs:      plaintext: %v, key: %v
Expecting:   encrypted: %v
Actual:      encrypted: %v
Fail
`, test.plaintext, test.key, test.expected, encrypted)
		} else {
			passCount++
			fmt.Printf(`---------------------------------
Inputs:      plaintext: %v, key: %v
Expecting:   encrypted: %v
Actual:      encrypted: %v
Pass
`, test.plaintext, test.key, test.expected, encrypted)
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
