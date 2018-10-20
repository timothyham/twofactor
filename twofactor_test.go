package main

import (
	_ "fmt"
	"strings"
	"testing"
)

type test struct {
	secret string
	time int64
	code string
}

func TestHash(t *testing.T) {
	testCases := make([]test, 0)

	testCases = append(testCases, test{"AAAAA", 12345, "435833"})
	testCases = append(testCases, test{"AAAAAA", 12345, "435833"})
	testCases = append(testCases, test{"ID2SDHZNEOTFV5V5", 12345, "375402"})
	testCases = append(testCases, test{"AAAAA", 12640, "016105"})
	testCases = append(testCases, test{"id2sdhzneotfv5v5", 12345, "375402"})
	testCases = append(testCases, test{"id2s dhzn eotf v5v5", 12345, "375402"})

	for _, test := range testCases {
		res := GoogleAuthCode(test.secret, test.time)
		if res != test.code {
			t.Errorf("Expected %s but got %s for secret '%s':%d", test.code, res, test.secret, test.time)
		}
	}
}

func TestReadConfigFile(t *testing.T) {

	s := `test:AAAAAA
test2:AAAAAAA
test3:ID2SDHZNEOTFV5V5`

	r := strings.NewReader(s)
	l, k := ReadConfigFile(r)

	if l[0] != "test" || k[0] != "AAAAAA" {
		t.Error("test")
	}

	if l[1] != "test2" || k[1] != "AAAAAAA" {
		t.Error("test2")
	}
	if l[2] != "test3" || k[2] != "ID2SDHZNEOTFV5V5" {
		t.Error("test3")
	}
}
