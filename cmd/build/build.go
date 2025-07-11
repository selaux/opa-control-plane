package cmd

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	"github.com/styrainc/lighthouse/cmd"
	"github.com/styrainc/lighthouse/cmd/internal/flags"
	"github.com/styrainc/lighthouse/internal/config"
	"github.com/styrainc/lighthouse/internal/logging"
	"github.com/styrainc/lighthouse/internal/progress"
	"github.com/styrainc/lighthouse/internal/service"
	"github.com/styrainc/lighthouse/internal/util"
	"github.com/styrainc/lighthouse/libraries"
)

type buildParams struct {
	silent            bool
	configFile        []string
	persistenceDir    string
	resetPersistence  bool
	mergeConflictFail bool
	logging           logging.Config
}

func init() {
	var params buildParams

	build := &cobra.Command{
		Use:   "build",
		Short: "Build and distribute configured bundles",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()

			var log *logging.Logger
			if params.silent {
				log = logging.NewLogger(params.logging)
			}

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
				WithSingleShot(true).
				WithLogger(log).
				WithSilent(params.silent)

			if err := svc.Run(ctx); err != nil {
				log.Fatal(err.Error())
			}
		},
	}

	flags.AddConfig(build.Flags(), &params.configFile)
	build.Flags().StringVarP(&params.persistenceDir, "data-dir", "d", "data", "Path to the persistence directory")
	build.Flags().BoolVarP(&params.resetPersistence, "reset-persistence", "", false, "Reset the persistence directory (for development purposes)")
	build.Flags().BoolVarP(&params.mergeConflictFail, "merge-conflict-fail", "", false, "Fail on config merge conflicts")
	progress.Var(build.Flags(), &params.silent)
	logging.VarP(build, &params.logging)

	cmd.RootCommand.AddCommand(
		build,
	)
}
