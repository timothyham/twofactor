package main

import (
	"encoding/binary"
	"net"
	"time"
)

// This file contains code from https://github.com/vladimirvivien/go-ntp-client
// MIT License
// Copyright (c) 2017 Vladimir Vivien
const ntpEpochOffset = 2208988800

// NTP packet format (v3 with optional v4 fields removed)
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |LI | VN  |Mode |    Stratum     |     Poll      |  Precision   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Root Delay                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Root Dispersion                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Reference ID                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                     Reference Timestamp (64)                  +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                      Origin Timestamp (64)                    +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                      Receive Timestamp (64)                   +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                      Transmit Timestamp (64)                  +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
type packet struct {
	Settings       uint8  // leap yr indicator, ver number, and mode
	Stratum        uint8  // stratum of local clock
	Poll           int8   // poll exponent
	Precision      int8   // precision exponent
	RootDelay      uint32 // root delay
	RootDispersion uint32 // root dispersion
	ReferenceID    uint32 // reference id
	RefTimeSec     uint32 // reference timestamp sec
	RefTimeFrac    uint32 // reference timestamp fractional
	OrigTimeSec    uint32 // origin time secs
	OrigTimeFrac   uint32 // origin time fractional
	RxTimeSec      uint32 // receive time secs
	RxTimeFrac     uint32 // receive time frac
	TxTimeSec      uint32 // transmit time secs
	TxTimeFrac     uint32 // transmit time frac
}

func GetNtpTime() (*time.Time, error) {
	// Setup a UDP connection
	ntpPool := "pool.ntp.org:123"
	conn, err := net.Dial("udp", ntpPool)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(1000 * time.Millisecond)); err != nil {
		return nil, err
	}
	// configure request settings by specifying the first byte as
	// 00 011 011 (or 0x1B)
	// |  |   +-- client mode (3)
	// |  + ----- version (3)
	// + -------- leap year indicator, 0 no warning
	req := &packet{Settings: 0x1B}

	// send time request
	if err := binary.Write(conn, binary.BigEndian, req); err != nil {
		return nil, err
	}

	// block to receive server response
	rsp := &packet{}
	if err := binary.Read(conn, binary.BigEndian, rsp); err != nil {
		return nil, err
	}

	// On POSIX-compliant OS, time is expressed
	// using the Unix time epoch (or secs since year 1970).
	// NTP seconds are counted since 1900 and therefore must
	// be corrected with an epoch offset to convert NTP seconds
	// to Unix time by removing 70 yrs of seconds (1970-1900)
	// or 2208988800 seconds.
	secs := float64(rsp.TxTimeSec) - ntpEpochOffset
	nanos := (int64(rsp.TxTimeFrac) * 1e9) >> 32 // convert fractional to nanos

	t := time.Unix(int64(secs), nanos)

	return &t, nil
}
