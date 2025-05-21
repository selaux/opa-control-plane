package cmd

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/spf13/cobra"
	"github.com/tsandall/lighthouse/internal/config"
	"gopkg.in/yaml.v3"
)

var envoyLibPath = "libraries/experimental/envoy-v1"
var refsHeadsMain = "refs/heads/main"

var builtinLibraries = []*config.Library{
	{
		Name: "template.envoy:2.1",
		Git: config.Git{
			Repo:      "/Users/torin/go/src/github.com/styrainc/lighthouse",
			Reference: &refsHeadsMain,
			Path:      &envoyLibPath,
		},
	},
}

type migrateParams struct {
	token string
	url   string
}

func init() {

	var params migrateParams

	params.token = os.Getenv("STYRA_TOKEN")

	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate configuration and policies from Styra",
		Run: func(cmd *cobra.Command, args []string) {
			if err := doMigrate(params); err != nil {
				log.Fatal(err)
			}
		},
	}

	cmd.Flags().StringVarP(&params.url, "url", "u", "", "Styra tenant URL (e.g., https://expo.styra.com)")

	RootCommand.AddCommand(
		cmd,
	)
}

func doMigrate(params migrateParams) error {
	if params.url == "" {
		return errors.New("please set Styra DAS URL with -u flag (e.g., https://example.styra.com)")
	}

	if params.token == "" {
		return errors.New("please set STYRA_TOKEN environment variable to token with WorkspaceViewer permission")
	}

	c := DASClient{
		url:    params.url,
		token:  params.token,
		client: http.DefaultClient,
	}

	output := config.Root{
		Systems:   map[string]*config.System{},
		Secrets:   map[string]*config.Secret{},
		Libraries: map[string]*config.Library{},
		Stacks:    map[string]*config.Stack{},
	}

	output.Metadata.ExportedFrom = params.url
	output.Metadata.ExportedAt = time.Now().UTC().Format(time.RFC3339)

	log.Println("Fetching v1/systems...")
	resp, err := c.JSON("v1/systems")
	if err != nil {
		return err
	}

	var systems []*v1System
	err = resp.Decode(&systems)
	if err != nil {
		return err
	}

	log.Printf("Received %d systems.", len(systems))

	log.Println("Fetching v1/libraries...")
	resp, err = c.JSON("v1/libraries")
	if err != nil {
		return err
	}

	var libraries []*v1Library
	err = resp.Decode(&libraries)
	if err != nil {
		return err
	}

	log.Printf("Received %d libraries.", len(libraries))

	log.Println("Fetching v1/stacks...")
	resp, err = c.JSON("v1/stacks")
	if err != nil {
		return err
	}

	var stacks []*v1Stack
	err = resp.Decode(&stacks)
	if err != nil {
		return err
	}
	log.Printf("Received %d stacks.", len(stacks))

	for _, library := range libraries {
		lc, secret, err := mapV1LibraryToLibraryAndSecretConfig(library)
		if err != nil {
			return err
		}

		output.Libraries[lc.Name] = lc
		if secret != nil {
			output.Secrets[secret.Name] = secret
		}
	}

	for _, bi := range builtinLibraries {
		output.Libraries[bi.Name] = bi
	}

	for _, system := range systems {
		sc, secret, err := migrateV1System(&c, system)
		if err != nil {
			return err
		}

		output.Systems[sc.Name] = sc
		if secret != nil {
			output.Secrets[secret.Name] = secret
		}
	}

	for _, stack := range stacks {
		sc, lc, secret, err := migrateV1Stack(&c, stack)
		if err != nil {
			return err
		}

		output.Stacks[sc.Name] = sc
		output.Libraries[lc.Name] = lc

		if secret != nil {
			output.Secrets[secret.Name] = secret
		}
	}

	log.Printf("Finished downloading resources from DAS. Printing migration configuration.")

	bs, err := yaml.Marshal(output)
	if err != nil {
		return err
	}

	fmt.Println(string(bs))

	v1StacksById := map[string]*v1Stack{}
	for _, stack := range stacks {
		v1StacksById[stack.Id] = stack
	}

	v1SystemsByName := map[string]*v1System{}
	for _, system := range systems {
		v1SystemsByName[system.Name] = system
	}

	for _, system := range output.Systems {
		matches := ast.NewSet()
		for _, stack := range output.Stacks {
			if stack.Selector.Matches(system.Labels) {
				matches.Add(ast.StringTerm(stack.Name))
			}
		}
		expectedMatches := ast.NewSet()
		for _, stackId := range v1SystemsByName[system.Name].MatchingStacks {
			expectedMatches.Add(ast.StringTerm(v1StacksById[stackId].Name))
		}
		missing := expectedMatches.Diff(matches)
		extra := matches.Diff(expectedMatches)
		if missing.Len() > 0 {
			log.Printf("System %q has missing stacks %v", system.Name, missing)
		}
		if extra.Len() > 0 {
			log.Printf("System %q has extra stacks %v", system.Name, extra)
		}
	}

	for _, stack := range output.Stacks {
		if _, ok := stack.Selector["do-not-match"]; ok {
			log.Printf("Stack %q did not match any systems. Consider removing it.", stack.Name)
		}
	}

	return nil
}

func getGitRoots(client *DASClient, v1 *v1System) ([]string, error) {

	resp, err := client.JSON("v1/systems/" + v1.Id + "/bundles")
	if err != nil {
		return nil, err
	}

	bundles := []*v1Bundle{}
	if err := resp.Decode(&bundles); err != nil {
		return nil, err
	}

	if len(bundles) > 0 {
		var roots []string
		for i := range bundles[0].SBOM.Origins {
			roots = append(roots, bundles[0].SBOM.Origins[i].Roots...)
		}
		return roots, nil
	}

	return nil, nil
}

func migrateV1System(client *DASClient, v1 *v1System) (*config.System, *config.Secret, error) {

	system, secret, err := mapV1SystemToSystemAndSecretConfig(client, v1)
	if err != nil {
		return nil, nil, err
	}

	log.Printf("Fetching policies for system %q", v1.Name)

	roots, err := getGitRoots(client, v1)
	if err != nil {
		return nil, nil, err
	}

	for i := range v1.Policies {
		if !rootsPrefix(roots, v1.Policies[i].Id) {
			resp, err := client.JSON("v1/policies/" + v1.Policies[i].Id)
			if err != nil {
				if dErr, ok := err.(DASError); ok && dErr.StatusCode == http.StatusNotFound {
					log.Printf("System %q refers to non-existent policy: %v", system.Name, v1.Policies[i].Id)
					continue
				}
				return nil, nil, err
			}
			var p v1Policy
			if err := resp.Decode(&p); err != nil {
				return nil, nil, err
			}
			if system.Files == nil {
				system.Files = make(map[string]string)
			}
			for file, str := range p.Modules {
				system.Files[strings.TrimPrefix(v1.Policies[i].Id, "systems/"+v1.Id)+"/"+file] = str
			}
		}
	}

	resp, err := client.JSON(fmt.Sprintf("v1/data/metadata/%v/labels", v1.Id))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query labels for %q: %w", v1.Name, err)
	}

	if len(resp.Result) > 0 {
		var x struct {
			Labels config.Labels `json:"labels"`
		}
		if err := resp.Decode(&x); err != nil {
			return nil, nil, fmt.Errorf("failed to decode labels for %q: %w", v1.Name, err)
		}
		system.Labels = x.Labels
		system.Labels["system-type"] = v1.Type // TODO(tsandall): remove template. prefix?
	}

	for _, bi := range builtinLibraries {
		if bi.Name == v1.Type {
			system.Requirements = append(system.Requirements, config.Requirement{
				Library: &bi.Name,
			})
		}
	}

	return system, secret, nil
}

func migrateV1Stack(client *DASClient, v1 *v1Stack) (*config.Stack, *config.Library, *config.Secret, error) {

	var stack config.Stack
	var library config.Library

	stack.Name = v1.Name
	library.Name = v1.Name

	log.Printf("Fetching policies for stack %q", v1.Name)
	// TODO(tsandall): add support for excluding git backed files
	// may need to pick a bundle from a matching system to pull out roots
	for i := range v1.Policies {
		resp, err := client.JSON("v1/policies/" + v1.Policies[i].Id)
		if err != nil {
			if dErr, ok := err.(DASError); ok && dErr.StatusCode == http.StatusNotFound {
				log.Printf("Stack %q refers to non-existent policy: %v", stack.Name, v1.Policies[i].Id)
				continue
			}
			return nil, nil, nil, err
		}
		var p v1Policy
		if err := resp.Decode(&p); err != nil {
			return nil, nil, nil, err
		}
		if library.Files == nil {
			library.Files = make(map[string]string)
		}
		for file, str := range p.Modules {
			library.Files[v1.Policies[i].Id+"/"+file] = str
		}
	}

	resp, err := client.JSON(fmt.Sprintf("v1/policies/stacks/%v/selectors", v1.Id))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get selector policy for %q: %w", v1.Name, err)
	}

	var p v1Policy
	if err := resp.Decode(&p); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode selector policy for %q: %w", v1.Name, err)
	}

	s, ok := p.Modules["selector.rego"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("missing selector.rego file for %q: %w", v1.Name, err)
	}

	module, err := ast.ParseModule("selector.rego", s)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse selector policy for %q: %w", v1.Name, err)
	}

	stack.Selector, err = migrateV1Selector(module)
	stack.Selector["system-type"] = []string{v1.Type}

	return &stack, &library, nil, err
}

func migrateV1Selector(module *ast.Module) (config.Selector, error) {
	selector := config.Selector{}
	for _, r := range module.Rules {
		if !r.Head.Name.Equal(ast.Var("systems")) {
			continue
		}
		var innerErr error
		ast.WalkExprs(r, func(x *ast.Expr) bool {
			if innerErr != nil {
				return true
			}
			if len(selector) > 0 {
				return true
			}
			if x.IsAssignment() {
				ops := x.Operands()
				if ops[0].Equal(ast.VarTerm("include")) {
					val, err := ast.JSON(ops[1].Value)
					if err != nil {
						innerErr = err
						return true
					}
					obj, ok := val.(map[string]interface{})
					if !ok {
						innerErr = fmt.Errorf("unexpected selector value structure: %v", ops[1])
						return true
					}
					for k, vs := range obj {
						sl, ok := vs.([]interface{})
						if !ok {
							innerErr = fmt.Errorf("unexpected selector list structure: %v", ops[1])
							return true
						}
						for _, v := range sl {
							s, ok := v.(string)
							if !ok {
								innerErr = fmt.Errorf("unexpected selector label structure: %v", ops[1])
								return true
							}
							selector[k] = append(selector[k], s)
						}
					}
				}
			}
			return false
		})
		if innerErr != nil {
			return nil, innerErr
		}
	}

	// NOTE(tsandall): DAS matching also takes into account the type information on the system/stack
	// since we don't have those in Lighthouse we need to exclude stacks that have an empty selector
	// because otherwise an empty selector matches ALL systems.
	//
	// NOTE(tsandall): users should just remove stacks from DAS with empty selectors.
	if len(selector) == 0 {
		selector["do-not-match"] = []string{}
	}
	return selector, nil
}
