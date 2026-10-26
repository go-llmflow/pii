//go:build !darwin && !linux

package main

func loadAvg1() (float64, error) { return 0, errNoLoad }
