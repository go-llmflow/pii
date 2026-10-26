package main

import "syscall"

// loadAvg1 reads sysctl vm.loadavg (decoded by decodeDarwinLoadavg).
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
