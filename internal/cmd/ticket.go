package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/connesc/ctrsigcheck"
	"github.com/spf13/cobra"
)

func init() {
	ticketCmd.Flags().AddFlagSet(&processFlags)
	rootCmd.AddCommand(ticketCmd)
}

type ticketFile struct {
	File *string
	*ctrsigcheck.Ticket
}

var ticketCmd = &cobra.Command{
	Use:   "ticket [file...]",
	Short: "Check ticket files",
	Long:  "Check ticket files given as arguments, or stdin if none is given",
	Run: func(cmd *cobra.Command, args []string) {
		processFiles(args, func(filename *string, input io.Reader) interface{} {
			ticket, err := ctrsigcheck.CheckTicket(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid ticket: %v\n", err)
				os.Exit(3)
			}
			return ticketFile{
				File:   filename,
				Ticket: ticket,
			}
		})
	},
}
