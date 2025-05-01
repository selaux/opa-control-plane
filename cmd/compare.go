package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/akedrou/textdiff"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/spf13/cobra"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/s3"
)

type compareReport struct {
	MissingSystems []string                       `json:"missing_systems"`
	Systems        map[string]compareSystemReport `json:"systems"`
}

type compareSystemReport struct {
	Bundle compareBundleReport `json:"bundle"`
}

type compareBundleReport struct {
	Rego compareRegoReport `json:"rego"`
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

	var sortedSystems []*config.System
	for _, system := range cfg.Systems {
		sortedSystems = append(sortedSystems, system)
	}

	sort.Slice(sortedSystems, func(i, j int) bool {
		return sortedSystems[i].Name < sortedSystems[j].Name
	})

	_ = url

	ctx := context.Background()

	styra := DASClient{url: params.styraURL, token: params.styraToken, client: http.DefaultClient}
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

	for _, system := range sortedSystems {
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

		// TODO(tsandall): ideally this would be addressed upstream or fixed within the builder
		for i := range a.Modules {
			a.Modules[i].Path = strings.TrimPrefix(a.Modules[i].Path, "/")
		}

		resp, err := styra.JSON("v1/systems/" + v1SystemsByName[system.Name].Id + "/bundles")
		if err != nil {
			return err
		}

		var v1bundles []*v1Bundle
		if err := resp.Decode(&v1bundles); err != nil {
			return err
		}

		downloadResp, err := styra.Get(strings.TrimPrefix(v1bundles[0].DownloadURL, styra.url))
		if err != nil {
			return err
		}

		err = func() error {
			defer downloadResp.Body.Close()

			b, err := bundle.NewReader(downloadResp.Body).Read()
			if err != nil {
				return err
			}

			bundleReport := compareBundle(a, b)
			result.Systems[system.Name] = compareSystemReport{Bundle: bundleReport}

			return nil
		}()
		if err != nil {
			return err
		}
	}

	bs, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(bs))

	return nil
}

func compareBundle(a, b bundle.Bundle) compareBundleReport {
	r := compareBundleReport{
		Rego: compareRegoReport{
			Diffs: map[string]string{},
		},
	}

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
			r.Rego.Extras = append(r.Rego.Extras, k)
		}
	}

	for k := range bFiles {
		if _, ok := aFiles[k]; !ok {
			r.Rego.Missing = append(r.Rego.Missing, k)
		}
	}

	for k := range aFiles {
		if _, ok := bFiles[k]; ok {
			if !bytes.Equal(aFiles[k], bFiles[k]) {
				r.Rego.Diffs[k] = textdiff.Unified("Expected", "Found", string(bFiles[k]), string(aFiles[k]))
			}
		}
	}

	return r
}

type v1Bundle struct {
	DownloadURL string `json:"download_url"`
	Origins     []struct {
		Roots []string `json:"roots"`
	}
}
