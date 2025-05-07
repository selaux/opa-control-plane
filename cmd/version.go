package cmd

import (
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	Version   = "0.0.0-dev"
	GoVersion = runtime.Version()
	Platform  = runtime.GOOS + "/" + runtime.GOARCH
)

func init() {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version of Lighthouse",
		Long:  "Show version and build information for Lighthouse.",
		Run: func(cmd *cobra.Command, args []string) {
			generateCmdOutput(os.Stdout)
		},
	}

	RootCommand.AddCommand(
		cmd,
	)
}

func generateCmdOutput(out io.Writer) {
	fmt.Fprintln(out, "Version: "+Version)
	fmt.Fprintln(out, "Go Version: "+GoVersion)
	fmt.Fprintln(out, "Platform: "+Platform)
}
