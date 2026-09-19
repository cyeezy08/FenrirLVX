package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func init() {
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print Fenrir build information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("fenrir %s (%s)\n", Version, Commit)
		},
	}
	rootCmd.AddCommand(versionCmd)
}
