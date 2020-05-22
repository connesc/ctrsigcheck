package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/connesc/ctrsigcheck"
	"github.com/spf13/cobra"
)

func init() {
	ciaCmd.Flags().AddFlagSet(&processFlags)
	rootCmd.AddCommand(ciaCmd)
}

type ciaFile struct {
	File *string
	*ctrsigcheck.CIA
}

var ciaCmd = &cobra.Command{
	Use:   "cia [file...]",
	Short: "Check CIA files",
	Long:  "Check CIA files given as arguments, or stdin if none is given",
	Run: func(cmd *cobra.Command, args []string) {
		processFiles(args, func(filename *string, input io.Reader) interface{} {
			cia, err := ctrsigcheck.CheckCIA(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid CIA: %v\n", err)
				os.Exit(3)
			}
			return ciaFile{
				File: filename,
				CIA:  cia,
			}
		})
	},
}
