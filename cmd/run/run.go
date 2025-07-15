package cmd

import (
	"bytes"
	"context"
	"os"

	"github.com/spf13/cobra"
	"github.com/styrainc/lighthouse/cmd"
	"github.com/styrainc/lighthouse/cmd/internal/flags"
	"github.com/styrainc/lighthouse/internal/config"
	"github.com/styrainc/lighthouse/internal/logging"
	"github.com/styrainc/lighthouse/internal/server"
	"github.com/styrainc/lighthouse/internal/service"
	"github.com/styrainc/lighthouse/internal/util"
	"github.com/styrainc/lighthouse/libraries"
)

const defaultLocalAddr = "localhost:8282"

type runParams struct {
	addr              string
	configFile        []string
	persistenceDir    string
	resetPersistence  bool
	mergeConflictFail bool
	logging           logging.Config
}

func init() {
	var params runParams

	run := &cobra.Command{
		Use:   "run",
		Short: "Run the Lighthouse service",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()

			log := logging.NewLogger(params.logging)

			if params.resetPersistence {
				if err := os.RemoveAll(params.persistenceDir); err != nil {
					log.Fatalf("failed to remove persistence directory: %v", err)
				}
			}
			if err := os.MkdirAll(params.persistenceDir, 0755); err != nil {
				log.Fatalf("failed to create persistence directory: %v", err)
			}

			bs, err := config.Merge(params.configFile, params.mergeConflictFail)
			if err != nil {
				log.Fatalf("configuration error: %v", err)
			}

			config, err := config.Parse(bytes.NewBuffer(bs))
			if err != nil {
				log.Fatalf("configuration error: %v", err)
			}

			svc := service.New().
				WithPersistenceDir(params.persistenceDir).
				WithConfig(config).
				WithBuiltinFS(util.NewEscapeFS(libraries.FS)).
				WithLogger(log)

			go func() {
				if err := server.New().WithDatabase(svc.Database()).Init().ListenAndServe(params.addr); err != nil {
					log.Fatalf("failed to start server: %v", err)
				}
			}()

			if err := svc.Run(ctx); err != nil {
				log.Fatal(err.Error())
			}
		},
	}

	flags.AddConfig(run.Flags(), &params.configFile)
	run.Flags().StringVarP(&params.addr, "addr", "a", defaultLocalAddr, "Set listening address of the server")
	run.Flags().StringVarP(&params.persistenceDir, "data-dir", "d", "data", "Path to the persistence directory")
	run.Flags().BoolVarP(&params.resetPersistence, "reset-persistence", "", false, "Reset the persistence directory (for development purposes)")
	run.Flags().BoolVarP(&params.mergeConflictFail, "merge-conflict-fail", "", false, "Fail on config merge conflicts")
	logging.VarP(run, &params.logging)

	cmd.RootCommand.AddCommand(
		run,
	)
}
