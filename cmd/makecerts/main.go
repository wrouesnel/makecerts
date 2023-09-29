//go:build !test
// +build !test

package main

import (
	"fmt"
	"os"
)

func main() {
	defer func() {
		err := recover()
		fmt.Println(err) //nolint:forbidigo
		os.Exit(1)
	}()

	if err := realMain(); err != nil {
		os.Exit(1) //nolint:gocritic
	}
	os.Exit(0)
}
