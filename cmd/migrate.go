package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	neturl "net/url"
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

var builtinLibraries = []*config.Library{
	{
		Name: "template.envoy:2.1",
		Requirements: []config.Requirement{
			{Library: strptr("template.envoy:2.1-entrypoint-application")},
			{Library: strptr("template.envoy:2.1-entrypoint-main")},
			{Library: strptr("template.envoy:2.1-entrypoint-authz")},
			{Library: strptr("template.envoy:2.1-entrypoint-log")},
			{Library: strptr("template.envoy:2.1-conflicts")},
		},
	},
	{
		Name:    "template.envoy:2.1-entrypoint-application",
		Builtin: strptr("envoy-v2.1/application"),
	},
	{
		Name:    "template.envoy:2.1-entrypoint-main",
		Builtin: strptr("envoy-v2.1/main"),
	},
	{
		Name:    "template.envoy:2.1-entrypoint-authz",
		Builtin: strptr("envoy-v2.1/authz"),
	},
	{
		Name:    "template.envoy:2.1-entrypoint-log",
		Builtin: strptr("envoy-v2.1/log"),
	},
	{
		Name:    "template.envoy:2.1-conflicts",
		Builtin: strptr("envoy-v2.1/conflicts"),
	},
	{
		Name:    "match-v1",
		Builtin: strptr("match-v1"),
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

func mapV1LibraryToLibraryAndSecretConfig(v1 *v1Library) (*config.Library, *config.Secret, error) {

	if v1.SourceControl.UseWorkspaceSettings {
		// TODO(tsandall): need to find library that has this
		// presumably need to export secret from workspace
		return nil, nil, fmt.Errorf("workspace source control not supported yet")
	}

	var library config.Library
	var secret *config.Secret

	library.Name = v1.Id

	if v1.SourceControl.LibraryOrigin.URL == "" {
		return &library, nil, nil
	}

	library.Git.Repo = v1.SourceControl.LibraryOrigin.URL

	if v1.SourceControl.LibraryOrigin.Commit != "" {
		library.Git.Commit = &v1.SourceControl.LibraryOrigin.Commit
	} else if v1.SourceControl.LibraryOrigin.Reference != "" {
		library.Git.Reference = &v1.SourceControl.LibraryOrigin.Reference
	}

	if v1.SourceControl.LibraryOrigin.Path != "" {
		library.Git.Path = &v1.SourceControl.LibraryOrigin.Path
	}

	if v1.SourceControl.LibraryOrigin.Credentials != "" {
		secret = &config.Secret{}
		secret.Name = v1.SourceControl.LibraryOrigin.Credentials
		library.Git.Credentials = &config.SecretRef{Name: secret.Name}
	} else if v1.SourceControl.LibraryOrigin.SSHCredentials.PrivateKey != "" {
		secret = &config.Secret{}
		secret.Name = v1.SourceControl.LibraryOrigin.SSHCredentials.PrivateKey
		library.Git.Credentials = &config.SecretRef{Name: secret.Name}
	}

	return &library, secret, nil
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
			// TODO(tsandall): pull N instead of just one (conflicts, mask, authz, etc.)
			system.Requirements = append(system.Requirements, config.Requirement{
				Library: &bi.Name,
			})
		}
	}

	return system, secret, nil
}

func mapV1SystemToSystemAndSecretConfig(_ *DASClient, v1 *v1System) (*config.System, *config.Secret, error) {
	var system config.System
	var secret *config.Secret

	system.Name = v1.Name

	if v1.SourceControl != nil {
		system.Git.Repo = v1.SourceControl.Origin.URL

		if v1.SourceControl.Origin.Commit != "" {
			system.Git.Commit = &v1.SourceControl.Origin.Commit
		} else if v1.SourceControl.Origin.Reference != "" {
			system.Git.Reference = &v1.SourceControl.Origin.Reference
		}

		if v1.SourceControl.Origin.Path != "" {
			system.Git.Path = &v1.SourceControl.Origin.Path
		}

		if v1.SourceControl.Origin.Credentials != "" {
			secret = &config.Secret{}
			secret.Name = v1.SourceControl.Origin.Credentials
			system.Git.Credentials = &config.SecretRef{Name: secret.Name}
		} else if v1.SourceControl.Origin.SSHCredentials.PrivateKey != "" {
			secret = &config.Secret{}
			secret.Name = v1.SourceControl.Origin.SSHCredentials.PrivateKey
			system.Git.Credentials = &config.SecretRef{Name: secret.Name}
		}
	}

	return &system, secret, nil
}

func migrateV1Stack(_ *DASClient, state *dasState, v1 *v1Stack) (*config.Stack, *config.Library, *config.Secret, error) {

	var stack config.Stack
	var library config.Library

	stack.Name = v1.Name
	library.Name = v1.Name
	stack.Requirements = append(stack.Requirements, config.Requirement{Library: &v1.Name})

	// NOTE(tsandall): automatically add requirement on match library as all stacks have selectors
	library.Requirements = append(library.Requirements, config.Requirement{Library: strptr("match-v1")})

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

	for _, p := range policies {
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
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to migrate selector for %q: %w", v1.Name, err)
			}
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

func migrateDependencies(_ *DASClient, state *dasState, output *config.Root) error {

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

type v1System struct {
	Id            string          `json:"id"`
	Name          string          `json:"name"`
	Type          string          `json:"type"`
	Policies      []v1PoliciesRef `json:"policies"`
	SourceControl *struct {
		Origin v1GitRepoConfig `json:"origin"`
	} `json:"source_control"`
	MatchingStacks []string `json:"matching_stacks"`
}

type v1Library struct {
	Id            string          `json:"id"`
	Policies      []v1PoliciesRef `json:"policies"`
	SourceControl *struct {
		UseWorkspaceSettings bool            `json:"use_workspace_settings"`
		LibraryOrigin        v1GitRepoConfig `json:"library_origin"`
	} `json:"source_control"`
}

type v1Stack struct {
	Name          string          `json:"name"`
	Id            string          `json:"id"`
	Type          string          `json:"type"`
	Policies      []v1PoliciesRef `json:"policies"`
	SourceControl *struct {
		UseWorkspaceSettings bool            `json:"use_workspace_settings"`
		Origin               v1GitRepoConfig `json:"origin"`
		StackOrigin          v1GitRepoConfig `json:"stack_origin"`
	} `json:"source_control"`
}

type v1GitRepoConfig struct {
	Commit         string `json:"commit"`
	Path           string `json:"path"`
	Reference      string `json:"reference"`
	Credentials    string `json:"credentials"`
	SSHCredentials struct {
		Passphrase string `json:"passphrase"`
		PrivateKey string `json:"private_key"`
	} `json:"ssh_credentials"`
	URL string `json:"url"`
}

type v1Bundle struct {
	DownloadURL string `json:"download_url"`
	SBOM        struct {
		Origins []struct {
			Roots []string `json:"roots"`
		} `json:"origins"`
	} `json:"sbom"`
}

type v1Decisions struct {
	Items []v1Decision `json:"items"`
}

type v1Decision struct {
	DecisionId string `json:"decision_id"`
	Bundles    map[string]struct {
		Revision string `json:"revision"`
	} `json:"bundles"`
	Path   string       `json:"path"`
	Input  *interface{} `json:"input"`
	Result *interface{} `json:"result"`
}

type v1PoliciesRef struct {
	Id string `json:"id"`
}

type v1Policy struct {
	Package string            `json:"package"`
	Modules map[string]string `json:"modules"`
}

type DASClient struct {
	url    string
	token  string
	client *http.Client
}

type DASResponse struct {
	Result    json.RawMessage `json:"result"`
	RequestId string          `json:"request_id"`
}

func (r *DASResponse) Decode(x interface{}) error {
	buf := bytes.NewBuffer(r.Result)
	decoder := json.NewDecoder(buf)
	return decoder.Decode(x)
}

type DASParams struct {
	Query map[string]string
}

func (c *DASClient) Get(path string, params ...DASParams) (*http.Response, error) {
	url := fmt.Sprintf("%v/%v", c.url, "/"+strings.TrimPrefix(path, "/"))

	var p DASParams
	if len(params) > 0 {
		p = params[0]
	}

	if len(p.Query) > 0 {

		qps := []string{}
		for key, value := range p.Query {
			qps = append(qps, fmt.Sprintf("%v=%v", neturl.QueryEscape(key), neturl.QueryEscape(value)))
		}

		url += "?" + strings.Join(qps, "&")
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("authorization", fmt.Sprintf("Bearer %v", c.token))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, DASError{URL: url, Method: "GET", StatusCode: resp.StatusCode}
	}

	return resp, nil

}

type DASError struct {
	URL        string
	Method     string
	StatusCode int
}

func (e DASError) Error() string {
	return fmt.Sprintf("DAS returned unexpected status code (%v) for %v %v", e.StatusCode, e.Method, e.URL)
}

func (c *DASClient) JSON(path string, params ...DASParams) (*DASResponse, error) {

	resp, err := c.Get(path, params...)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var r DASResponse
	return &r, decoder.Decode(&r)
}

func rootsPrefix(roots []string, path string) bool {
	for _, r := range roots {
		if path == r {
			return true
		}
		if strings.HasPrefix(path, r+"/") {
			return true
		}
	}
	return false
}

func strptr(s string) *string { return &s }
