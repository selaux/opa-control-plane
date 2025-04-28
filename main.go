package main

import (
	"os"

	"github.com/tsandall/lighthouse/cmd"
)

func main() {
	if err := cmd.RootCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
