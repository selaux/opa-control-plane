package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/akedrou/textdiff"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/spf13/cobra"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/s3"
)

type compareReport struct {
	MissingSystems []string                       `json:"missing_systems,omitempty"`
	ExtraSystems   []string                       `json:"extra_systems,omitempty"`
	Systems        map[string]compareSystemReport `json:"systems,omitempty"`
}

type compareSystemReport struct {
	Error  *string              `json:"error,omitempty"`
	Bundle *compareBundleReport `json:"bundle,omitempty"`
}

type compareBundleReport struct {
	Rego *compareRegoReport `json:"rego,omitempty"`
}

func (r *compareBundleReport) init() {
	r.Rego = &compareRegoReport{Diffs: map[string]string{}}
}

func (r *compareBundleReport) AddExtra(path string) {
	r.init()
	r.Rego.Extras = append(r.Rego.Extras, path)
}

func (r *compareBundleReport) AddMissing(path string) {
	r.init()
	r.Rego.Missing = append(r.Rego.Missing, path)
}

func (r *compareBundleReport) AddDiff(path, blob string) {
	r.init()
	r.Rego.Diffs[path] = blob
}

func (r *compareBundleReport) Empty() bool {
	if r.Rego == nil {
		return true
	}
	return len(r.Rego.Missing) == 0 && len(r.Rego.Extras) == 0 && len(r.Rego.Diffs) == 0
}

type compareRegoReport struct {
	Missing []string          `json:"missing,omitempty"`
	Extras  []string          `json:"extras,omitempty"`
	Diffs   map[string]string `json:"diffs,omitempty"`
}

type compareParams struct {
	configFile string
	styraURL   string
	styraToken string
}

func init() {

	var params compareParams

	params.styraToken = os.Getenv("STYRA_TOKEN")

	cmd := &cobra.Command{
		Use:   "compare",
		Short: "Compare Lighthouse configuration and bundles to version from Styra",
		Run: func(cmd *cobra.Command, args []string) {
			if err := doCompare(params); err != nil {
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

func doCompare(params compareParams) error {

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
		return errors.New("please provide Styra URL with -u/--url")
	}

	var sortedSystems []*config.System
	for _, system := range cfg.Systems {
		sortedSystems = append(sortedSystems, system)
	}

	sort.Slice(sortedSystems, func(i, j int) bool {
		return sortedSystems[i].Name < sortedSystems[j].Name
	})

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

	_ = styra

	result := compareReport{
		Systems: map[string]compareSystemReport{},
	}

	for name := range v1SystemsByName {
		if _, ok := cfg.Systems[name]; !ok {
			result.MissingSystems = append(result.MissingSystems, name)
		}
	}

	ctx := context.Background()

	for _, system := range sortedSystems {
		v1, ok := v1SystemsByName[system.Name]
		if !ok {
			result.ExtraSystems = append(result.ExtraSystems, system.Name)
			continue
		}
		report, err := compareSystem(ctx, &styra, v1, system)
		if err != nil {
			msg := err.Error()
			report = &compareSystemReport{Error: &msg}
		}
		result.Systems[system.Name] = *report
	}

	bs, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(bs))

	return nil
}

func compareSystem(ctx context.Context, client *DASClient, v1 *v1System, system *config.System) (*compareSystemReport, error) {

	log.Printf("Checking system %q...", system.Name)

	s, err := s3.New(ctx, system.ObjectStorage)
	if err != nil {
		return nil, err
	}
	r, err := s.Download(ctx)
	if err != nil {
		return nil, err
	}
	a, err := bundle.NewReader(r).Read()
	if err != nil {
		return nil, err
	}

	// TODO(tsandall): ideally this would be addressed upstream or fixed within the builder
	for i := range a.Modules {
		a.Modules[i].Path = strings.TrimPrefix(a.Modules[i].Path, "/")
	}

	resp, err := client.JSON("v1/systems/" + v1.Id + "/bundles")
	if err != nil {
		return nil, err
	}

	var v1bundles []*v1Bundle
	if err := resp.Decode(&v1bundles); err != nil {
		return nil, err
	}

	downloadResp, err := client.Get(strings.TrimPrefix(v1bundles[0].DownloadURL, client.url))
	if err != nil {
		return nil, err
	}

	defer downloadResp.Body.Close()

	b, err := bundle.NewReader(downloadResp.Body).Read()
	if err != nil {
		return nil, err
	}

	bundleReport, err := compareBundle(a, b)
	result := &compareSystemReport{Bundle: &bundleReport}
	if err != nil {
		msg := err.Error()
		result.Error = &msg
	}
	return result, nil
}

func compareBundle(a, b bundle.Bundle) (compareBundleReport, error) {

	var r compareBundleReport

	aFiles := map[string][]byte{}
	for _, mf := range a.Modules {
		aFiles[mf.Path] = mf.Raw
	}

	bFiles := map[string][]byte{}
	for _, mf := range b.Modules {
		bFiles[mf.Path] = mf.Raw
	}

	for k := range aFiles {
		if _, ok := bFiles[k]; !ok {
			r.AddExtra(k)
		}
	}

	for k := range bFiles {
		if _, ok := aFiles[k]; !ok {
			r.AddMissing(k)
		}
	}

	for k := range aFiles {
		if _, ok := bFiles[k]; ok {
			am, err := ast.ParseModule(k, string(aFiles[k]))
			if err != nil {
				return r, err
			}

			bm, err := ast.ParseModule(k, string(bFiles[k]))
			if err != nil {
				return r, err
			}

			if !am.Equal(bm) {
				r.AddDiff(k, textdiff.Unified("Expected", "Found", string(bFiles[k]), string(aFiles[k])))
			}
		}
	}

	if !reflect.DeepEqual(a.Data, b.Data) {

		aBytes, err := json.MarshalIndent(a.Data, "", "  ")
		if err != nil {
			return r, err
		}

		bBytes, err := json.MarshalIndent(b.Data, "", "  ")
		if err != nil {
			return r, err
		}

		diffText := textdiff.Unified("Expected", "Found", string(bBytes), string(aBytes))
		if len(diffText) > 1024 {
			diffText = diffText[:1024]
		}

		r.AddDiff("data.json", diffText)
	}

	return r, nil
}
