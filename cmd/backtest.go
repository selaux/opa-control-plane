package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/akedrou/textdiff"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/rego"
	"github.com/spf13/cobra"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/s3"
)

type backtestParams struct {
	configFile   string
	styraURL     string
	styraToken   string
	numDecisions int
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
	cmd.Flags().IntVarP(&params.numDecisions, "decisions", "n", 100, "Number of decisions to backtest")

	RootCommand.AddCommand(
		cmd,
	)

}

type backtestReport struct {
	ExtraSystems     []string          `json:"extra_systems,omitempty"`
	MissingDecisions []string          `json:"missing_decisions,omitempty"`
	Systems          map[string]string `json:"systems,omitempty"`
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
		return fmt.Errorf("please provide Styra URL with -u/--url")
	}

	styra := DASClient{
		url:    url,
		token:  params.styraToken,
		client: http.DefaultClient}

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

	report := backtestReport{
		Systems: map[string]string{},
	}

	ctx := context.Background()

	for _, system := range cfg.Systems {
		if err := backtestSystem(ctx, params.numDecisions, &styra, v1SystemsByName, system, &report); err != nil {
			report.Systems[system.Name] = err.Error()
		}
	}

	bs, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stdout, string(bs))

	return nil
}

func backtestSystem(ctx context.Context, n int, styra *DASClient, byName map[string]*v1System, system *config.System, report *backtestReport) error {

	v1, ok := byName[system.Name]
	if !ok {
		report.ExtraSystems = append(report.ExtraSystems, system.Name)
		return nil
	}

	resp, err := styra.JSON("v1/decisions", DASParams{
		Query: map[string]string{
			"limit":  fmt.Sprintf("%d", n),
			"system": v1.Id,
		},
	})
	if err != nil {
		return err
	}

	var decisions v1Decisions

	if err := resp.Decode(&decisions); err != nil {
		return err
	}

	if len(decisions.Items) == 0 {
		report.MissingDecisions = append(report.MissingDecisions, system.Name)
		return nil
	}

	s, err := s3.New(ctx, system.ObjectStorage)
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
			return errors.New("logged decision was undefined but bundle decision was not")
		}
		return nil
	}

	if len(rs) == 0 {
		return errors.New("logged decision was defined but bundle decision was not")
	}

	a, err := ast.InterfaceToValue(rs[0].Expressions[0].Value)
	if err != nil {
		return err
	}

	b, err := ast.InterfaceToValue(*d.Result)
	if err != nil {
		return err
	}

	if a.Compare(b) != 0 {

		aBytes, err := json.MarshalIndent(rs[0].Expressions[0].Value, "", "  ")
		if err != nil {
			return err
		}

		bBytes, err := json.MarshalIndent(*d.Result, "", "  ")
		if err != nil {
			return err
		}

		return errors.New(textdiff.Unified("Expected", "Found", string(bBytes), string(aBytes)))
	}

	return nil
}
