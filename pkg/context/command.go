package context

import (
	"github.com/spf13/cobra"
	"gitlab.casa-systems.com/platform/go/axyom/version"
	"os"
)

func newCommand() *cobra.Command {
	versionCmd := &cobra.Command{
		Use: "version",
		Run: func(cmd *cobra.Command, args []string) {
			version.ShowVersion()
			os.Exit(0)
		},
	}

	rootCmd := &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {},
	}

	rootCmd.AddCommand(versionCmd)
	return rootCmd
}
