package main

import (
	"os"

	"github.com/tsandall/lighthouse/cmd"
	_ "github.com/tsandall/lighthouse/cmd/backtest"
	_ "github.com/tsandall/lighthouse/cmd/compare"
	_ "github.com/tsandall/lighthouse/cmd/migrate"
	_ "github.com/tsandall/lighthouse/cmd/run"
	_ "github.com/tsandall/lighthouse/cmd/version"
)

func main() {
	if err := cmd.RootCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
