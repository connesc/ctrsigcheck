package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/connesc/ctrsigcheck"
)

func main() {
	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open CIA: %v\n", err)
		os.Exit(1)
	}

	info, err := ctrsigcheck.CheckCIA(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to check CIA: %v\n", err)
		os.Exit(2)
	}

	output := json.NewEncoder(os.Stdout)
	output.SetIndent("", "  ")
	output.SetEscapeHTML(false)
	output.Encode(info)
}
