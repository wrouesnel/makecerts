//go:build !test
// +build !test

package main

import (
	"fmt"
	"os"

	"github.com/wrouesnel/makecerts/internal/entrypoint"
)

func main() {
	defer func() {
		err := recover()
		fmt.Println(err) //nolint:forbidigo
		os.Exit(1)
	}()

	if err := entrypoint.Entrypoint(os.Stdout, os.Stderr, os.Stdin); err != nil {
		os.Exit(1) //nolint:gocritic
	}
	os.Exit(0)
}
