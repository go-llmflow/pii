package main

import (
	"encoding/binary"
	"errors"
)

// decodeDarwinLoadavg decodes struct loadavg { fixpt_t ldavg[3]; long
// fscale; } (uint32 ×3, padding, int64), little-endian on darwin's 64-bit
// targets. Pure decoding, so that it is tested on every platform.
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
