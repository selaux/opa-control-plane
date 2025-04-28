package cmd

import (
	"os"
	"path"

	"github.com/spf13/cobra"
)

// RootCommand is the base CLI command that all subcommands are added to.
var RootCommand = &cobra.Command{
	Use:   path.Base(os.Args[0]),
	Short: "Lighthouse",
	Long:  "An open source control plane for Open Policy Agent (OPA).",
}
