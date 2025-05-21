package cmd

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
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

	state, err := fetchDASState(&c)
	if err != nil {
		return err
	}

	for _, library := range state.LibrariesById {
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

	for _, system := range state.SystemsById {
		sc, secret, err := migrateV1System(&c, state, system)
		if err != nil {
			return err
		}

		output.Systems[sc.Name] = sc
		if secret != nil {
			output.Secrets[secret.Name] = secret
		}
	}

	for _, stack := range state.StacksById {
		sc, lc, secret, err := migrateV1Stack(&c, state, stack)
		if err != nil {
			return err
		}

		output.Stacks[sc.Name] = sc
		output.Libraries[lc.Name] = lc

		if secret != nil {
			output.Secrets[secret.Name] = secret
		}
	}

	if err := migrateDependencies(&c, state, &output); err != nil {
		return err
	}

	log.Printf("Finished downloading resources from DAS. Printing migration configuration.")

	bs, err := yaml.Marshal(output)
	if err != nil {
		return err
	}

	fmt.Println(string(bs))

	v1SystemsByName := map[string]*v1System{}
	for _, system := range state.SystemsById {
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
			expectedMatches.Add(ast.StringTerm(state.StacksById[stackId].Name))
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
		if _, ok := stack.Selector.Get("do-not-match"); ok {
			log.Printf("Stack %q did not match any systems. Consider removing it.", stack.Name)
		}
	}

	return nil
}

func migrateV1System(client *DASClient, state *dasState, v1 *v1System) (*config.System, *config.Secret, error) {

	system, secret, err := mapV1SystemToSystemAndSecretConfig(client, v1)
	if err != nil {
		return nil, nil, err
	}

	log.Printf("Fetching git roots and labels for system %q", v1.Name)

	resp, err := client.JSON("v1/systems/" + v1.Id + "/bundles")
	if err != nil {
		return nil, nil, err
	}

	bundles := []*v1Bundle{}
	if err := resp.Decode(&bundles); err != nil {
		return nil, nil, err
	}

	var roots []string

	if len(bundles) > 0 {
		for i := range bundles[0].SBOM.Origins {
			roots = append(roots, bundles[0].SBOM.Origins[i].Roots...)
		}
	}

	policies := state.SystemPolicies[v1.Id]
	for i := range policies {
		if !rootsPrefix(roots, policies[i].Package) {
			if system.Files == nil {
				system.Files = make(map[string]string)
			}
			for file, str := range policies[i].Modules {
				system.Files[strings.TrimPrefix(policies[i].Package, "systems/"+v1.Id)+"/"+file] = str
			}
		}
	}

	resp, err = client.JSON(fmt.Sprintf("v1/data/metadata/%v/labels", v1.Id))
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

func migrateV1Stack(client *DASClient, state *dasState, v1 *v1Stack) (*config.Stack, *config.Library, *config.Secret, error) {

	var stack config.Stack
	var library config.Library

	stack.Name = v1.Name
	library.Name = v1.Name
	stack.Requirements = append(stack.Requirements, config.Requirement{Library: &v1.Name})

	// TODO(tsandall): add support for excluding git backed files
	// may need to pick a bundle from a matching system to pull out roots
	policies := state.StackPolicies[v1.Id]

	for i := range policies {
		if library.Files == nil {
			library.Files = make(map[string]string)
		}
		for file, str := range policies[i].Modules {
			library.Files[policies[i].Package+"/"+file] = str
		}
	}

	pkg := fmt.Sprintf("stacks/%v/selectors", v1.Id)

	for _, p := range state.StackPolicies[v1.Id] {
		if p.Package == pkg {
			s, ok := p.Modules["selector.rego"]
			if !ok {
				return nil, nil, nil, fmt.Errorf("missing selector.rego file for %q", v1.Name)
			}

			module, err := ast.ParseModule("selector.rego", s)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to parse selector policy for %q: %w", v1.Name, err)
			}

			stack.Selector, err = migrateV1Selector(module)
			err = stack.Selector.Set("system-type", []string{v1.Type})
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to set system-type label for %q: %w", v1.Name, err)
			}

			return &stack, &library, nil, err
		}
	}

	return nil, nil, nil, fmt.Errorf("misisng selector policy for %q", v1.Name)
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
			if selector.Len() > 0 {
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

							l, _ := selector.Get(k)
							err := selector.Set(k, append(l, s))
							if err != nil {
								innerErr = err
								return true
							}
						}
					}
				}
			}
			return false
		})
		if innerErr != nil {
			return config.Selector{}, innerErr
		}
	}

	// NOTE(tsandall): DAS matching also takes into account the type information on the system/stack
	// since we don't have those in Lighthouse we need to exclude stacks that have an empty selector
	// because otherwise an empty selector matches ALL systems.
	//
	// NOTE(tsandall): users should just remove stacks from DAS with empty selectors.
	var err error
	if selector.Len() == 0 {
		err = selector.Set("do-not-match", []string{})
	}
	return selector, err
}

type dasState struct {
	SystemsById     map[string]*v1System
	SystemPolicies  map[string][]*v1Policy
	StacksById      map[string]*v1Stack
	StackPolicies   map[string][]*v1Policy
	LibrariesById   map[string]*v1Library
	LibraryPolicies map[string][]*v1Policy
}

func fetchDASState(c *DASClient) (*dasState, error) {
	state := dasState{}

	log.Println("Fetching v1/systems")
	resp, err := c.JSON("v1/systems")
	if err != nil {
		return nil, err
	}

	var systems []*v1System
	err = resp.Decode(&systems)
	if err != nil {
		return nil, err
	}

	log.Println("Fetching v1/libraries")
	resp, err = c.JSON("v1/libraries")
	if err != nil {
		return nil, err
	}

	var libraries []*v1Library
	err = resp.Decode(&libraries)
	if err != nil {
		return nil, err
	}

	log.Println("Fetching v1/stacks")
	resp, err = c.JSON("v1/stacks")
	if err != nil {
		return nil, err
	}

	var stacks []*v1Stack
	err = resp.Decode(&stacks)
	if err != nil {
		return nil, err
	}

	state.SystemsById = map[string]*v1System{}
	for _, s := range systems {
		state.SystemsById[s.Id] = s
	}

	state.StacksById = map[string]*v1Stack{}
	for _, s := range stacks {
		state.StacksById[s.Id] = s
	}

	state.LibrariesById = map[string]*v1Library{}
	for _, l := range libraries {
		state.LibrariesById[l.Id] = l
	}

	if err := fetchSystemPolicies(c, &state); err != nil {
		return nil, err
	}

	if err := fetchStackPolicies(c, &state); err != nil {
		return nil, err
	}

	if err := fetchLibraryPolicies(c, &state); err != nil {
		return nil, err
	}

	return &state, nil
}

func migrateDependencies(c *DASClient, state *dasState, output *config.Root) error {

	index := newLibraryPackageIndex()

	for id, policies := range state.LibraryPolicies {
		for _, p := range policies {
			index.Add(p.Package, id)
		}
	}

	for id, policies := range state.SystemPolicies {
		rs, err := getRequirementsForPolicies(policies, index, "")
		if err != nil {
			return err
		}

		sc := output.Systems[state.SystemsById[id].Name]
		sc.Requirements = append(sc.Requirements, rs...)
	}

	for id, policies := range state.StackPolicies {
		rs, err := getRequirementsForPolicies(policies, index, "")
		if err != nil {
			return err
		}
		lc := output.Libraries[state.StacksById[id].Name]
		lc.Requirements = append(lc.Requirements, rs...)
	}

	for id, policies := range state.LibraryPolicies {
		rs, err := getRequirementsForPolicies(policies, index, id)
		if err != nil {
			return err
		}
		lc := output.Libraries[id]
		lc.Requirements = append(lc.Requirements, rs...)
	}

	return nil
}

func fetchSystemPolicies(c *DASClient, state *dasState) error {
	ch := make(chan *v1System)
	var wg sync.WaitGroup
	var mu sync.Mutex

	state.SystemPolicies = map[string][]*v1Policy{}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			for s := range ch {
				log.Printf("Fetching %d policies for system %q", len(s.Policies), s.Name)
				ps, err := fetchPolicies(c, s.Policies)
				if err != nil {
					panic(err)
				}
				mu.Lock()
				state.SystemPolicies[s.Id] = ps
				mu.Unlock()
			}
			wg.Done()
		}()
	}

	for _, s := range state.SystemsById {
		ch <- s
	}

	close(ch)
	wg.Wait()
	return nil
}

func fetchStackPolicies(c *DASClient, state *dasState) error {
	ch := make(chan *v1Stack)
	var wg sync.WaitGroup
	var mu sync.Mutex

	state.StackPolicies = map[string][]*v1Policy{}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			for s := range ch {
				log.Printf("Fetching %d policies for stack %q", len(s.Policies), s.Name)
				ps, err := fetchPolicies(c, s.Policies)
				if err != nil {
					panic(err)
				}
				mu.Lock()
				state.StackPolicies[s.Id] = ps
				mu.Unlock()
			}
			wg.Done()
		}()
	}

	for _, s := range state.StacksById {
		ch <- s
	}

	close(ch)
	wg.Wait()
	return nil
}

func fetchLibraryPolicies(c *DASClient, state *dasState) error {
	ch := make(chan *v1Library)
	var wg sync.WaitGroup
	var mu sync.Mutex

	state.LibraryPolicies = map[string][]*v1Policy{}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			for l := range ch {

				// List libraries differs from systems/stacks. Result does not
				// have policies on it. Need to fetch each library individually.
				resp, err := c.JSON("v1/libraries/"+l.Id, DASParams{
					Query: map[string]string{
						"rule_counts": "false",
						"modules":     "false",
					},
				})
				if err != nil {
					panic(err)
				}

				if err := resp.Decode(l); err != nil {
					panic(err)
				}

				log.Printf("Fetching %d policies for library %q", len(l.Policies), l.Id)
				ps, err := fetchPolicies(c, l.Policies)
				if err != nil {
					panic(err)
				}

				mu.Lock()
				state.LibrariesById[l.Id] = l
				state.LibraryPolicies[l.Id] = ps
				mu.Unlock()
			}
			wg.Done()
		}()
	}

	for _, l := range state.LibrariesById {
		ch <- l
	}

	close(ch)
	wg.Wait()
	return nil
}

func fetchPolicies(c *DASClient, refs []v1PoliciesRef) ([]*v1Policy, error) {
	var result []*v1Policy
	for _, ref := range refs {
		resp, err := c.JSON("v1/policies/" + ref.Id)
		if err != nil {
			if dErr, ok := err.(DASError); ok && dErr.StatusCode == http.StatusNotFound {
				log.Printf("Non-existent policy reference: %v", ref.Id)
				continue
			}
			return nil, err
		}
		var p v1Policy
		if err := resp.Decode(&p); err != nil {
			return nil, err
		}
		p.Package = ref.Id
		result = append(result, &p)
	}
	return result, nil
}

func getRequirementsForPolicies(policies []*v1Policy, index *libraryPackageIndex, ignore string) ([]config.Requirement, error) {
	librarySet := map[string]struct{}{}
	for _, p := range policies {
		for file, content := range p.Modules {
			module, err := ast.ParseModule(p.Package+"/"+file, content)
			if err != nil {
				return nil, err
			}
			var innerErr error
			ast.WalkRefs(module, func(r ast.Ref) bool {
				if !r.HasPrefix(ast.DefaultRootRef) {
					return false
				}
				ptr, err := r.ConstantPrefix().Ptr()
				if err != nil {
					innerErr = err
					return false
				}
				libraries := index.Lookup(ptr)
				for id := range libraries {
					if id != ignore {
						librarySet[id] = struct{}{}
					}
				}
				return false
			})
			if innerErr != nil {
				return nil, innerErr
			}
		}
	}
	var rs []config.Requirement
	for id := range librarySet {
		rs = append(rs, config.Requirement{Library: &id})
	}
	sort.Slice(rs, func(i, j int) bool {
		return *rs[i].Library < *rs[j].Library
	})
	return rs, nil
}

type libraryPackageIndex struct {
	nodes   map[string]*libraryPackageIndex
	library string
}

func newLibraryPackageIndex() *libraryPackageIndex {
	return &libraryPackageIndex{
		nodes: map[string]*libraryPackageIndex{},
	}
}

func (idx *libraryPackageIndex) Lookup(path string) map[string]struct{} {
	result := map[string]struct{}{}
	keys := strings.Split(path, "/")
	curr := idx
	for _, key := range keys {
		node, ok := curr.nodes[key]
		if !ok {
			return result
		}
		if node.library != "" {
			result[node.library] = struct{}{}
		}
		curr = node
	}
	visit := []*libraryPackageIndex{curr}
	for len(visit) > 0 {
		var next *libraryPackageIndex
		next, visit = visit[0], visit[1:]
		if next.library != "" {
			result[next.library] = struct{}{}
		}
		for _, node := range next.nodes {
			visit = append(visit, node)
		}
	}
	return result
}

func (idx *libraryPackageIndex) Add(path string, lib string) {
	keys := strings.Split(path, "/")
	curr := idx
	for _, key := range keys {
		node, ok := curr.nodes[key]
		if !ok {
			node = newLibraryPackageIndex()
			curr.nodes[key] = node
		}
		curr = node
	}
	curr.library = lib
}
