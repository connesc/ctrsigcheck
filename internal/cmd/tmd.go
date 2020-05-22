package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/connesc/ctrsigcheck"
	"github.com/spf13/cobra"
)

func init() {
	tmdCmd.Flags().AddFlagSet(&processFlags)
	rootCmd.AddCommand(tmdCmd)
}

type tmdFile struct {
	File *string
	*ctrsigcheck.TMD
}

var tmdCmd = &cobra.Command{
	Use:   "tmd [file...]",
	Short: "Check TMD files",
	Long:  "Check TMD files given as arguments, or stdin if none is given",
	Run: func(cmd *cobra.Command, args []string) {
		processFiles(args, func(filename *string, input io.Reader) interface{} {
			tmd, err := ctrsigcheck.CheckTMD(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid TMD: %v\n", err)
				os.Exit(3)
			}
			return tmdFile{
				File: filename,
				TMD:  tmd,
			}
		})
	},
}
