package backtest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/akedrou/textdiff"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/rego"
	"github.com/spf13/cobra"
	"github.com/tsandall/lighthouse/cmd"
	"github.com/tsandall/lighthouse/cmd/internal/das"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/s3"
)

type Options struct {
	ConfigFile   []string
	URL          string
	Token        string
	NumDecisions int
	Output       io.Writer
}

func init() {
	var params Options

	params.Token = os.Getenv("STYRA_TOKEN")

	backtest := &cobra.Command{
		Use:   "backtest",
		Short: "Run decision backtest on Lighthouse bundles against bundles from Styra",
		Run: func(cmd *cobra.Command, args []string) {
			params.Output = os.Stdout
			if err := Run(params); err != nil {
				log.Fatal(err)
			}
		},
	}

	backtest.Flags().StringSliceVarP(&params.ConfigFile, "config", "c", []string{"config.yaml"}, "Path to the configuration file")
	backtest.Flags().StringVarP(&params.URL, "url", "u", "", "Styra tenant URL (e.g., https://expo.styra.com)")
	backtest.Flags().IntVarP(&params.NumDecisions, "decisions", "n", 100, "Number of decisions to backtest")

	cmd.RootCommand.AddCommand(
		backtest,
	)

}

type Report struct {
	ExtraSystems     []string                `json:"extra_systems,omitempty"`
	MissingDecisions []string                `json:"missing_decisions,omitempty"`
	Systems          map[string]SystemReport `json:"systems,omitempty"`
}

type SystemReport struct {
	Status  string         `json:"status,omitempty"`
	Message string         `json:"message,omitempty"`
	Details []DecisionDiff `json:"details,omitempty"`
}

type DecisionDiff struct {
	Reason string `json:"reason"`
	Path   string `json:"path"`
}

func Run(params Options) error {

	bs, err := config.Merge(params.ConfigFile)
	if err != nil {
		return err
	}

	cfg, err := config.Parse(bytes.NewBuffer(bs))
	if err != nil {
		return err
	}

	url := cfg.Metadata.ExportedFrom

	if params.URL != "" {
		url = params.URL
	}

	if url == "" {
		return fmt.Errorf("please provide Styra URL with -u/--url")
	}

	styra := das.Client{
		URL:    url,
		Token:  params.Token,
		Client: http.DefaultClient}

	log.Println("Fetching systems")
	resp, err := styra.JSON("v1/systems")
	if err != nil {
		return err
	}

	var v1systems []*das.V1System
	if err := resp.Decode(&v1systems); err != nil {
		return err
	}

	v1SystemsByName := map[string]*das.V1System{}
	for _, system := range v1systems {
		v1SystemsByName[system.Name] = system
	}

	report := Report{
		Systems: map[string]SystemReport{},
	}

	ctx := context.Background()

	for _, system := range cfg.Systems {
		if err := backtestSystem(ctx, params.NumDecisions, &styra, v1SystemsByName, system, &report); err != nil {
			report.Systems[system.Name] = SystemReport{
				Status:  "error",
				Message: err.Error(),
			}
		}
	}

	bs, err = json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	fmt.Fprintln(params.Output, string(bs))

	return nil
}

func backtestSystem(ctx context.Context, n int, styra *das.Client, byName map[string]*das.V1System, system *config.System, report *Report) error {

	v1, ok := byName[system.Name]
	if !ok {
		report.ExtraSystems = append(report.ExtraSystems, system.Name)
		return nil
	}

	resp, err := styra.JSON("v1/decisions", das.Params{
		Query: map[string]string{
			"limit":  fmt.Sprintf("%d", n),
			"system": v1.Id,
		},
	})
	if err != nil {
		return err
	}

	var decisions das.V1Decisions

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

	t0 := time.Now()

	var diffs []DecisionDiff

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
			path, innerErr := saveFailure(&a, d)
			if innerErr != nil {
				return innerErr
			}
			diffs = append(diffs, DecisionDiff{Reason: err.Error(), Path: path})
		}
	}

	if len(diffs) == 0 {
		// TODO(tsandall): improve report to include latency comparison
		report.Systems[system.Name] = SystemReport{
			Status:  "passed",
			Message: fmt.Sprintf("evaluated %v decisions in %v and found no difference(s)", len(decisions.Items), time.Since(t0)),
		}
	} else {
		var reportLimit string
		nDiffs := len(diffs)
		if len(diffs) > 10 {
			diffs = diffs[:10]
			reportLimit = " (report limit: 10)"
		}
		report.Systems[system.Name] = SystemReport{
			Status:  "failed",
			Message: fmt.Sprintf("evaluated %v decisions in %v and found %v difference(s)%v", len(decisions.Items), time.Since(t0), nDiffs, reportLimit),
			Details: diffs,
		}
	}

	return nil
}

func saveFailure(b *bundle.Bundle, d das.V1Decision) (string, error) {

	path, err := os.MkdirTemp("", "lighthouse-backtest")
	if err != nil {
		return "", err
	}

	bundleFile, err := os.Create(filepath.Join(path, "bundle.tar.gz"))
	if err != nil {
		return "", err
	}

	defer bundleFile.Close()

	if err := bundle.NewWriter(bundleFile).DisableFormat(true).Write(*b); err != nil {
		return "", err
	}

	decisionFile, err := os.Create(filepath.Join(path, "decision.json"))
	if err != nil {
		return "", err
	}

	defer decisionFile.Close()

	enc := json.NewEncoder(decisionFile)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return "", err
	}

	inputFile, err := os.Create(filepath.Join(path, "input.json"))
	if err != nil {
		return "", err
	}

	defer inputFile.Close()

	enc = json.NewEncoder(inputFile)
	enc.SetIndent("", "  ")
	if enc.Encode(d.Input) != nil {
		return "", err
	}

	return path, nil
}

func compareResults(d *das.V1Decision, rs rego.ResultSet) error {

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
