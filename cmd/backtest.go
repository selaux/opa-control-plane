package cmd

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/rego"
	"github.com/spf13/cobra"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/s3"
)

type backtestParams struct {
	configFile string
	styraURL   string
	styraToken string
}

func init() {
	var params backtestParams

	params.styraToken = os.Getenv("STYRA_TOKEN")

	cmd := &cobra.Command{
		Use:   "backtest",
		Short: "Run decision backtest on Lighthouse bundles against bundles from Styra",
		Run: func(cmd *cobra.Command, args []string) {
			if err := doBacktest(params); err != nil {
				log.Fatal(err)
			}
		},
	}

	cmd.Flags().StringVarP(&params.configFile, "config", "c", "config.yaml", "Path to the configuration file")
	cmd.Flags().StringVarP(&params.styraURL, "url", "u", "", "Styra tenant URL (e.g., https://expo.styra.com)")

	RootCommand.AddCommand(
		cmd,
	)

}

func doBacktest(params backtestParams) error {

	log.Printf("Loading configuration from %v...", params.configFile)
	cfg, err := config.ParseFile(params.configFile)
	if err != nil {
		return err
	}

	url := cfg.Metadata.ExportedFrom

	if params.styraURL != "" {
		url = params.styraURL
	}

	if url == "" {
		return fmt.Errorf("Please provide Styra URL with -u/--url")
	}

	styra := DASClient{
		url:    url,
		token:  params.styraToken,
		client: http.DefaultClient}

	var sortedSystems []string
	for name := range cfg.Systems {
		sortedSystems = append(sortedSystems, name)
	}

	sort.Strings(sortedSystems)

	log.Println("Fetching systems...")
	resp, err := styra.JSON("v1/systems")
	if err != nil {
		return err
	}

	var v1systems []*v1System
	if err := resp.Decode(&v1systems); err != nil {
		return err
	}

	v1SystemsByName := map[string]*v1System{}
	for _, system := range v1systems {
		v1SystemsByName[system.Name] = system
	}

	var v1 *v1System
	var decisions v1Decisions

	for _, name := range sortedSystems {

		var ok bool
		v1, ok = v1SystemsByName[name]
		if !ok {
			continue
		}

		resp, err = styra.JSON("v1/decisions", DASParams{
			Query: map[string]string{
				"limit":  "10",
				"system": v1.Id,
			},
		})
		if err != nil {
			return err
		}

		if err := resp.Decode(&decisions); err != nil {
			return err
		}

		if len(decisions.Items) == 0 {
			continue
		}

		break
	}

	if len(decisions.Items) == 0 {
		return fmt.Errorf("Could not find any matching systems with decisions")
	}

	log.Printf("Picked system %q (%v)...", v1.Name, v1.Id)

	ctx := context.Background()

	s, err := s3.New(ctx, cfg.Systems[v1.Name].ObjectStorage)
	if err != nil {
		return err
	}

	r, err := s.Download(ctx)
	if err != nil {
		return err
	}

	a, err := bundle.NewReader(r).Read()
	if err != nil {
		return err
	}

	for _, d := range decisions.Items {

		var args []func(*rego.Rego)
		args = append(args, rego.ParsedBundle("", &a))
		path := []*ast.Term{ast.DefaultRootDocument}
		for _, k := range strings.Split(d.Path, "/") {
			path = append(path, ast.StringTerm(k))
		}

		args = append(args, rego.Query(ast.RefTerm(path...).String()))
		if d.Input != nil {
			args = append(args, rego.Input(*d.Input))
		}

		rs, err := rego.New(args...).Eval(ctx)
		if err != nil {
			return err
		}

		if err := compareResults(&d, rs); err != nil {
			return err
		}
	}

	return nil
}

func compareResults(d *v1Decision, rs rego.ResultSet) error {

	if d.Result == nil {
		if len(rs) > 0 {
			return fmt.Errorf("logged decision was undefined but bundle decision was not")
		}
		return nil
	}

	if len(rs) == 0 {
		return fmt.Errorf("logged decision was defined but bundle decision was not")
	}

	if !reflect.DeepEqual(rs[0].Expressions[0].Value, *d.Result) {
		return fmt.Errorf("decision %v differed from logged", d.DecisionId)
	}

	return nil
}
