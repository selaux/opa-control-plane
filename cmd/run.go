package cmd

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/tsandall/lighthouse/internal/server"
	"github.com/tsandall/lighthouse/internal/service"
	"github.com/tsandall/lighthouse/internal/util"
	"github.com/tsandall/lighthouse/libraries"
	"gopkg.in/yaml.v3"
)

const defaultLocalAddr = "localhost:8282"

type runParams struct {
	addr             string
	configFile       []string
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

			bs, err := getMergedConfig(params.configFile)
			if err != nil {
				log.Fatalf("configuration error: %v", err)
			}

			svc := service.New().
				WithPersistenceDir(params.persistenceDir).
				WithConfig(bs).
				WithBuiltinFS(util.NewEscapeFS(libraries.FS))

			go func() {
				if err := server.New().WithDatabase(svc.Database()).Init().ListenAndServe(params.addr); err != nil {
					log.Fatalf("failed to start server: %v", err)
				}
			}()

			if err := svc.Run(ctx); err != nil {
				log.Fatal(err)
			}
		},
	}

	cmd.Flags().StringVarP(&params.addr, "addr", "a", defaultLocalAddr, "set listening address of the server")
	cmd.Flags().StringSliceVarP(&params.configFile, "config", "c", []string{"config.yaml"}, "Path to the configuration file")
	cmd.Flags().StringVarP(&params.persistenceDir, "data-dir", "d", "data", "Path to the persistence directory")
	cmd.Flags().BoolVarP(&params.resetPersistence, "reset-persistence", "", false, "Reset the persistence directory (for development purposes)")

	RootCommand.AddCommand(
		cmd,
	)
}

func getMergedConfig(configFiles []string) ([]byte, error) {

	var docs []map[string]interface{}
	for _, f := range configFiles {
		bs, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("failed to read configuration file %v: %v", f, err)
		}
		var x map[string]interface{}
		if err := yaml.Unmarshal(bs, x); err != nil {
			return nil, fmt.Errorf("failed to unmarshal configuration file %v: %v", f, err)
		}
		docs = append(docs, x)
	}

	merged := merge(docs)
	bs, err := yaml.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal merged configuration: %v", err)
	}

	return bs, nil
}

func merge(docs []map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, doc := range docs {
		for key, value := range doc {
			if existing, ok := result[key]; ok {
				if existingMap, ok1 := existing.(map[string]interface{}); ok1 {
					if valueMap, ok2 := value.(map[string]interface{}); ok2 {
						result[key] = merge([]map[string]interface{}{existingMap, valueMap})
						continue
					}
				}
			}
			result[key] = value
		}
	}
	return result
}
