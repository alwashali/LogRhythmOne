package main

import "strings"

func splitNameHeader(header string) []string {
	LRs := strings.Split(strings.TrimSpace(header), " ")

	return LRs
}
