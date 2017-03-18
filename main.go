//+build !test

package main

import (
	"fmt"
	"os"
)

func main() {
	defer func() {
		err := recover()
		fmt.Println(err)
		os.Exit(1)
	}()

	if err := realMain(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
