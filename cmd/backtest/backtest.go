package backtest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/akedrou/textdiff"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/sdk"
	"github.com/spf13/cobra"
	"github.com/tsandall/lighthouse/cmd"
	"github.com/tsandall/lighthouse/cmd/internal/das"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/logging"
	"github.com/tsandall/lighthouse/internal/s3"
)

var log *logging.Logger

type Options struct {
	ConfigFile           []string
	URL                  string
	Token                string
	NumDecisions         int
	PolicyType           string
	MaxEvalTimeInflation int
	MergeConflictFail    bool
	Logging              logging.Config
	Output               io.Writer
}

func init() {
	var opts Options

	opts.Token = os.Getenv("STYRA_TOKEN")

	backtest := &cobra.Command{
		Use:   "backtest",
		Short: "Run backtest on Lighthouse bundles against decisions from Styra",
		Run: func(cmd *cobra.Command, args []string) {
			opts.Output = os.Stdout
			if err := Run(opts); err != nil {
				log.Fatal(err.Error())
			}
		},
	}

	backtest.Flags().StringSliceVarP(&opts.ConfigFile, "config", "c", []string{"config.yaml"}, "Path to the configuration file")
	backtest.Flags().StringVarP(&opts.URL, "url", "u", "", "Styra tenant URL (e.g., https://expo.styra.com)")
	backtest.Flags().IntVarP(&opts.NumDecisions, "decisions", "n", 100, "Number of decisions to backtest")
	backtest.Flags().StringVarP(&opts.PolicyType, "policy-type", "", "", "Specify policy type to backtest against (e.g., validating, mutating, etc.)")
	backtest.Flags().IntVarP(&opts.MaxEvalTimeInflation, "max-eval-time-inflation", "", 100, "Maximum allowed increase in decision evaluation time (in percents, <0 to disable)")
	backtest.Flags().BoolVarP(&opts.MergeConflictFail, "merge-conflict-fail", "", false, "Fail on config merge conflicts")
	logging.VarP(backtest, &opts.Logging)

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

func Run(opts Options) error {
	log = logging.NewLogger(opts.Logging)

	bs, err := config.Merge(opts.ConfigFile, opts.MergeConflictFail)
	if err != nil {
		return err
	}

	cfg, err := config.Parse(bytes.NewBuffer(bs))
	if err != nil {
		return err
	}

	url := cfg.Metadata.ExportedFrom

	if opts.URL != "" {
		url = opts.URL
	}

	if url == "" {
		return fmt.Errorf("please provide Styra URL with -u/--url")
	}

	styra := das.Client{
		URL:    url,
		Token:  opts.Token,
		Client: http.DefaultClient}

	log.Info("Fetching systems")
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
		log.Infof("Backtesting system %q", system.Name)
		if err := backtestSystem(ctx, opts, &styra, v1SystemsByName, system, &report); err != nil {
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

	fmt.Fprintln(opts.Output, string(bs))

	return nil
}

func backtestSystem(ctx context.Context, opts Options, styra *das.Client, byName map[string]*das.V1System, system *config.System, report *Report) error {

	v1, ok := byName[system.Name]
	if !ok {
		report.ExtraSystems = append(report.ExtraSystems, system.Name)
		return nil
	}

	params := das.Params{
		Query: map[string]string{
			"limit":  fmt.Sprintf("%d", opts.NumDecisions),
			"system": v1.Id,
		},
	}

	if opts.PolicyType != "" {
		params.Query["policy_type"] = opts.PolicyType
	}

	resp, err := styra.JSON("v1/decisions", params)
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

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	a, err := bundle.NewReader(bytes.NewReader(b)).Read()
	if err != nil {
		return err
	}

	t0 := time.Now()

	var diffs []DecisionDiff

	// Start a HTTP server for bundle.

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		files := map[string][]byte{
			"/bundle.tar.gz": b,
		}

		content, ok := files[r.URL.Path]
		if !ok {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}

		if _, err := w.Write([]byte(content)); err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))

	defer ts.Close()

	// Start OPA SDK

	config := fmt.Sprintf(`{
                "services": {
                        "test": {
                                "url": %q
                        }
                },
                "bundles": {
                        "test": {
                                "resource": "/bundle.tar.gz"
                        }
                }
        }`, ts.URL)

	ready := make(chan struct{})
	opa, err := sdk.New(ctx, sdk.Options{
		Config: strings.NewReader(config),
		Ready:  ready,
	})
	if err != nil {
		return err
	}

	defer opa.Stop(ctx)

	select {
	case <-time.After(15 * time.Second):
		return errors.New("OPA SDK did not become ready in time")
	case <-ctx.Done():
		return ctx.Err()
	case <-ready:
		// SDK is ready
	}

	// Re-evaluate decisions

	for _, d := range decisions.Items {

		options := sdk.DecisionOptions{
			Path: d.Path,
		}
		if d.Input != nil {
			options.Input = *d.Input
		}

		log.Infof("Evaluating decision %q for system %q", d.DecisionId, system.Name)

		var result *interface{}
		var start time.Time = time.Now()

		r, err := opa.Decision(ctx, options)
		if err != nil && !sdk.IsUndefinedErr(err) {
			return err
		} else if sdk.IsUndefinedErr(err) {
			result = nil
		} else {
			result = &r.Result
		}

		if err := compareResults(&d, result, time.Now().Sub(start), opts.MaxEvalTimeInflation); err != nil {
			path, innerErr := saveFailure(&a, d)
			if innerErr != nil {
				return innerErr
			}
			diffs = append(diffs, DecisionDiff{Reason: err.Error(), Path: path})
		}
	}

	if len(diffs) == 0 {
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

func compareResults(d *das.V1Decision, r *interface{}, t time.Duration, maxEvalInflation int) error {

	if d.Result == nil {
		if r != nil {
			return errors.New("logged decision was undefined but bundle decision was not")
		}
		return nil
	}

	if r == nil {
		return errors.New("logged decision was defined but bundle decision was not")
	}

	a, err := ast.InterfaceToValue(*r)
	if err != nil {
		return err
	}

	b, err := ast.InterfaceToValue(*d.Result)
	if err != nil {
		return err
	}

	if a.Compare(b) != 0 {

		aBytes, err := json.MarshalIndent(*r, "", "  ")
		if err != nil {
			return err
		}

		bBytes, err := json.MarshalIndent(*d.Result, "", "  ")
		if err != nil {
			return err
		}

		return errors.New(textdiff.Unified("Expected", "Found", string(bBytes), string(aBytes)))
	}

	if maxEvalInflation >= 0 {
		if o := time.Duration(d.Metrics.TimerRegoQueryEvalNs); o*time.Duration(maxEvalInflation+100)/100 < t {
			return fmt.Errorf("bundle decision took over %d%% longer than original decision to evaluate", maxEvalInflation)
		}
	}

	return nil
}
