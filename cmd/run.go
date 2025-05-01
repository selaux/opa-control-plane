package cmd

import (
	"context"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/tsandall/lighthouse/internal/service"
)

type runParams struct {
	configFile       string
	persistenceDir   string
	resetPersistence bool
}

func init() {
	var params runParams

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the Lighthouse service",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()
			if params.resetPersistence {
				if err := os.RemoveAll(params.persistenceDir); err != nil {
					log.Fatalf("failed to remove persistence directory: %v", err)
				}
			}
			if err := os.MkdirAll(params.persistenceDir, 0755); err != nil {
				log.Fatalf("failed to create persistence directory: %v", err)
			}
			svc := service.New().WithConfigFile(params.configFile).WithPersistenceDir(params.persistenceDir)
			if err := svc.Run(ctx); err != nil {
				log.Fatal(err)
			}
		},
	}

	cmd.Flags().StringVarP(&params.configFile, "config", "c", "config.yaml", "Path to the configuration file")
	cmd.Flags().StringVarP(&params.persistenceDir, "data-dir", "d", "data", "Path to the persistence directory")
	cmd.Flags().BoolVarP(&params.resetPersistence, "reset-persistence", "", false, "Reset the persistence directory (for development purposes)")

	RootCommand.AddCommand(
		cmd,
	)
}
