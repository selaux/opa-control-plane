package main

import (
	"os"

	"github.com/styrainc/lighthouse/cmd"
	_ "github.com/styrainc/lighthouse/cmd/backtest"
	_ "github.com/styrainc/lighthouse/cmd/compare"
	_ "github.com/styrainc/lighthouse/cmd/migrate"
	_ "github.com/styrainc/lighthouse/cmd/run"
	_ "github.com/styrainc/lighthouse/cmd/version"
)

func main() {
	if err := cmd.RootCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
