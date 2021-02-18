package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const FILENAME = ".twofactor"

var Debug = false

var debug = flag.Bool("d", false, "Debug")
var generate = flag.Bool("gen", false, "Generate code")
var genshort = flag.Bool("genshort", false, "Generate short code")
var help = flag.Bool("h", false, "show this help")
var noNTP = flag.Bool("nontp", false, "don't use NTP server")

func main() {
	flag.Parse()

	if *help {
		fmt.Printf("twofactor - print TOTP codes\n\n")
		fmt.Printf("twofactor [flags] [delta]\n")
		fmt.Printf("[delta] is used when the clock is not accurate. \n2- for one minute in the past, 2+ for in the future.\n")
		flag.PrintDefaults()
		os.Exit(0)
	}

	Debug = *debug
	if *generate || *genshort {
		key, err := Generate(*genshort)
		if err != nil {
			fmt.Printf("Error :%v\n", err)
		} else {
			fmt.Printf("%s\n", key)
		}
		os.Exit(0)
	}

	deltaFlag := flag.Arg(0)

	delta := 0
	negative := false
	hasSuffix := false
	if strings.HasSuffix(deltaFlag, "-") {
		negative = true
		hasSuffix = true
	} else if strings.HasSuffix(deltaFlag, "+") {
		hasSuffix = true
	}

	endIdx := len(deltaFlag)
	if hasSuffix {
		endIdx = endIdx - 1
	}
	delta, err := strconv.Atoi(deltaFlag[:endIdx])
	if err != nil {
		delta = 0
	}
	if negative {
		delta = delta * -1
	}

	if Debug {
		fmt.Printf("delta: %s\n", deltaFlag)
		fmt.Printf("deltaVal: %v\n", delta)
	}
	home := os.Getenv("HOME")
	configFile := home + "/" + FILENAME

	f, err := os.Open(configFile)
	defer f.Close()

	if err != nil {
		fmt.Println("Config file $HOME/.twofactor not found.")
		fmt.Println("The config file format is label:sharedsecret")
	}

	labels, keys := ReadConfigFile(f)

	validNTP := false
	var now *time.Time
	if *noNTP {
		tNow := time.Now()
		now = &tNow
	} else {
		tStart := time.Now()
		now, err = GetNtpTime()
		if err == nil {
			validNTP = true
		} else {
			fmt.Printf("No NTP: %v\n", err)
			tNow := time.Now()
			now = &tNow
		}
		if Debug {
			fmt.Printf("NTP time took %.2f: %s\n", time.Now().Sub(tStart).Seconds(), now.Format(time.RFC3339))
		}
	}

	if delta != 0 {
		offsetTime := now.Add(time.Duration(delta) * 30 * time.Second)
		now = &offsetTime
	}
	timeStr := now.Format(time.RFC3339)
	if validNTP {
		timeStr += " (NTP)"
	} else {
		timeStr += " (computer)"
	}
	fmt.Printf("Time: %s\n", timeStr)
	nowUnix := now.Unix()

	for i, label := range labels {
		code := GoogleAuthCode(keys[i], nowUnix)
		remaining := 30 - nowUnix%30
		fmt.Printf("%s : %s : %v : %vs\n", spaceCode(code), code, label, remaining)
	}
}

func spaceCode(code string) string {
	return code[:3] + " " + code[3:]
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
	secret = strings.ToUpper(secret)
	secret = strings.Replace(secret, " ", "", -1)
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

func Generate(short bool) (string, error) {
	var bits []byte
	if short {
		bits = make([]byte, 10)
	} else {
		bits = make([]byte, 20)
	}
	_, err := rand.Read(bits)
	if err != nil {
		return "", err
	}

	res := base32.StdEncoding.EncodeToString(bits)
	return res, nil
}
