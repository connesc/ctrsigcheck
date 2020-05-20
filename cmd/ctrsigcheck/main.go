package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/connesc/ctrsigcheck"
)

func main() {
	output := json.NewEncoder(os.Stdout)
	output.SetIndent("", "  ")
	output.SetEscapeHTML(false)

	if len(os.Args) <= 1 {
		processFile(nil, os.Stdin, output)
		return
	}

	for _, filename := range os.Args[1:] {
		file, err := os.Open(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to open CIA: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		processFile(&filename, file, output)
	}
}

type ciaFile struct {
	File *string
	*ctrsigcheck.CIA
}

func processFile(file *string, input io.Reader, output *json.Encoder) {
	cia, err := ctrsigcheck.CheckCIA(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to check CIA: %v\n", err)
		os.Exit(2)
	}
	output.Encode(ciaFile{
		File: file,
		CIA:  cia,
	})
}
