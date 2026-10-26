package main

import (
	"os"
	"strconv"
	"strings"
)

func loadAvg1() (float64, error) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, errNoLoad
	}
	return strconv.ParseFloat(f[0], 64)
}
