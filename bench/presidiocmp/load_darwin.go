package main

import (
	"encoding/binary"
	"errors"
	"syscall"
)

// loadAvg1 reads sysctl vm.loadavg: struct loadavg { fixpt_t ldavg[3]; long
// fscale; } (uint32 ×3, padding, int64), little-endian on darwin's 64-bit
// targets.
func loadAvg1() (float64, error) {
	raw, err := syscall.Sysctl("vm.loadavg")
	if err != nil {
		return 0, err
	}
	b := []byte(raw)
	for len(b) < 24 { // syscall.Sysctl drops a trailing NUL byte
		b = append(b, 0)
	}
	return decodeDarwinLoadavg(b)
}

func decodeDarwinLoadavg(b []byte) (float64, error) {
	if len(b) < 24 {
		return 0, errors.New("vm.loadavg too short")
	}
	ld := binary.LittleEndian.Uint32(b[0:4])
	fscale := int64(binary.LittleEndian.Uint64(b[16:24]))
	if fscale <= 0 {
		return 0, errors.New("vm.loadavg: bad fscale")
	}
	return float64(ld) / float64(fscale), nil
}
