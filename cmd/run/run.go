package cmd

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	"github.com/tsandall/lighthouse/cmd"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/logging"
	"github.com/tsandall/lighthouse/internal/server"
	"github.com/tsandall/lighthouse/internal/service"
	"github.com/tsandall/lighthouse/internal/util"
	"github.com/tsandall/lighthouse/libraries"
)

const defaultLocalAddr = "localhost:8282"

type runParams struct {
	addr              string
	configFile        []string
	persistenceDir    string
	resetPersistence  bool
	singleShot        bool
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

			svc := service.New().
				WithPersistenceDir(params.persistenceDir).
				WithConfig(bs).
				WithBuiltinFS(util.NewEscapeFS(libraries.FS)).
				WithSingleShot(params.singleShot).
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

	run.Flags().StringVarP(&params.addr, "addr", "a", defaultLocalAddr, "set listening address of the server")
	run.Flags().StringSliceVarP(&params.configFile, "config", "c", []string{"config.yaml"}, "Path to the configuration file")
	run.Flags().StringVarP(&params.persistenceDir, "data-dir", "d", "data", "Path to the persistence directory")
	run.Flags().BoolVarP(&params.resetPersistence, "reset-persistence", "", false, "Reset the persistence directory (for development purposes)")
	run.Flags().BoolVarP(&params.singleShot, "once", "", false, "Build system bundles only once")
	run.Flags().BoolVarP(&params.mergeConflictFail, "merge-conflict-fail", "", false, "Fail on config merge conflicts")
	logging.VarP(run, &params.logging)

	cmd.RootCommand.AddCommand(
		run,
	)
}
