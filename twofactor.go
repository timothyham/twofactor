package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const FILENAME = ".twofactor"

var Debug = false

func main() {
	home := os.Getenv("HOME")
	configFile := home + "/" + FILENAME

	f, err := os.Open(configFile)
	defer f.Close()

	if err != nil {
		fmt.Println("Config file $HOME/.twofactor not found.")
		fmt.Println("The config file format is label:sharedsecret")
	}

	labels, keys := ReadConfigFile(f)

	for i, label := range labels {
		now := time.Now().Unix()
		code := GoogleAuthCode(keys[i], now)
		remaining := 30 - now%30
		fmt.Printf("%s : %v : %vs\n", code, label, remaining)
	}
}

func ReadConfigFile(r io.Reader) ([]string, []string) {
	keys := make([]string, 0, 10)
	values := make([]string, 0, 10)

	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		keys = append(keys, fields[0])
		values = append(values, fields[1])
	}

	return keys, values
}

// Calculate HMAC-SHA1
func HmacSha1(key, msg []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	sum := mac.Sum(nil)

	return sum
}

func GoogleAuthCode(secret string, now int64) string {
	keyBytes, _ := base32.StdEncoding.DecodeString(secret)

	timeCounter := now / 30
	timeBytes := new(bytes.Buffer)
	binary.Write(timeBytes, binary.BigEndian, timeCounter)

	hash := HmacSha1(keyBytes, timeBytes.Bytes())

	if Debug {
		fmt.Printf("key: %v\n", keyBytes)
		fmt.Printf("timeCounter: %v\n", timeCounter)
		fmt.Printf("timeBuf: %x\n", timeBytes)
	}

	offset := hash[19] & 0xF
	if Debug {
		fmt.Printf("hash: %x\n", hash)
		fmt.Printf("hash: %o\n", hash)
		fmt.Printf("hash len: %v\n", len(hash))

		fmt.Printf("offset byte: %x\n", hash[19])
		fmt.Printf("offset: %x\n", offset)
		fmt.Printf("offsetValue: %v\n", offset)
	}

	truncatedHash := hash[offset : offset+4]
	truncatedHash[0] = truncatedHash[0] & 0x7F

	var code32 int32
	binary.Read(bytes.NewReader(truncatedHash), binary.BigEndian, &code32)
	code := int(code32)
	code = code % 1000000

	outputCode := strconv.Itoa(code)

	padding := len(outputCode)
	if len(outputCode) < 6 {
		for i := 0; i < 6-padding; i++ {
			outputCode = "0" + outputCode
		}
	}

	//outputCode = outputCode[0:3] + " " + outputCode[3:6]

	return outputCode
}
