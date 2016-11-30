package main

import (
	_ "fmt"
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	r1 := GoogleAuthCode("AAAAA", 12345)
	r2 := GoogleAuthCode("AAAAAA", 12345)
	r3 := GoogleAuthCode("ID2SDHZNEOTFV5V5", 12345)
	r4 := GoogleAuthCode("AAAAA", 12640)

	if r1 != "435833" {
		t.Error("r1")
	}
	if r2 != "435833" {
		t.Error("r2")
	}
	if r3 != "375402" {
		t.Error("r3")
	}
	if r4 != "016105" {
		t.Error("r4")
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
