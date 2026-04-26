package brute_force

import (
	"fmt"
	"testing"
)

func TestFindKey(t *testing.T) {
	type testCase struct {
		encrypted  []byte
		decrypted  string
		expected   []byte
		shouldFail bool
	}

	runCases := []testCase{
		{[]byte{0x1b, 0x2c, 0x3d}, "yes", []byte{0x62, 0x49, 0x4e}, false}, // Correct key for "yes" is 62 49 4e
		{[]byte{0x2a, 0xff, 0xea}, "car", []byte{0x49, 0x9e, 0x98}, false}, // Correct key for "car" is 49 9e 98
		{[]byte{0x7d, 0x31, 0x32}, "she", []byte{0x0e, 0x59, 0x57}, false}, // Correct key for "she" is 0e 59 57
	}

	submitCases := append(runCases, []testCase{
		{[]byte{0x2b, 0xff, 0xaa}, "top", []byte{0x5f, 0x90, 0xda}, false}, // Correct key for "top" is 5f 90 da
		{[]byte{0x1c, 0x4d, 0x5e}, "win", []byte{0x6b, 0x24, 0x30}, false}, // Correct key for "win" is 6b 24 30
	}...)

	testCases := runCases
	if withSubmit {
		testCases = submitCases
	}

	skipped := len(submitCases) - len(testCases)
	passCount := 0
	failCount := 0

	for _, test := range testCases {
		key, err := findKey(test.encrypted, test.decrypted)
		if (err != nil) != test.shouldFail {
			failCount++
			t.Errorf(`---------------------------------
Inputs:      encrypted: %v, decrypted: %v
Expecting:   Error: %v
Actual:      Error: %v
Fail
`, test.encrypted, test.decrypted, test.shouldFail, err != nil)
		} else if !test.shouldFail && string(key) != string(test.expected) {
			failCount++
			t.Errorf(`---------------------------------
Inputs:      encrypted: %v, decrypted: %v
Expecting:   Key: %x
Actual:      Key: %x
Fail
`, test.encrypted, test.decrypted, test.expected, key)
		} else {
			passCount++
			fmt.Printf(`---------------------------------
Inputs:      encrypted: %v, decrypted: %v
Expecting:   Key: %x
Actual:      Key: %x
Pass
`, test.encrypted, test.decrypted, test.expected, key)
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
