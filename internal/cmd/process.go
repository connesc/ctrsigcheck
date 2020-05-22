package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/pflag"
)

type processFunc func(filename *string, input io.Reader) interface{}

var (
	processFlags pflag.FlagSet
	compact      = processFlags.BoolP("compact", "c", false, "disable pretty-printing of JSON output")
)

func processFiles(filenames []string, process processFunc) {
	encoder := json.NewEncoder(os.Stdout)
	if !*compact {
		encoder.SetIndent("", "  ")
	}
	encoder.SetEscapeHTML(false)

	if len(os.Args) <= 1 {
		encoder.Encode(process(nil, os.Stdin))
		return
	}

	for _, filename := range filenames {
		processFile(filename, process, encoder)
	}
}

func processFile(filename string, process processFunc, encoder *json.Encoder) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open file: %v\n", err)
		os.Exit(2)
	}
	defer file.Close()

	encoder.Encode(process(&filename, file))
}
