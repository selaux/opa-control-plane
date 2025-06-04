package migrate

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/spf13/cobra"
	"github.com/tsandall/lighthouse/cmd"
	"github.com/tsandall/lighthouse/cmd/internal/das"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/logging"
	"github.com/tsandall/lighthouse/libraries"
	"gopkg.in/yaml.v3"
)

var log *logging.Logger

var systemTypeLibraries = []*config.Library{
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
		Name: "template.envoy:2.0",
		Requirements: []config.Requirement{
			{Library: strptr("template.envoy:2.0-entrypoint-application")},
			{Library: strptr("template.envoy:2.0-entrypoint-main")},
			{Library: strptr("template.envoy:2.0-entrypoint-authz")},
			{Library: strptr("template.envoy:2.0-entrypoint-log")},
			{Library: strptr("template.envoy:2.0-conflicts")},
		},
	},
	{
		Name: "template.istio:1.0",
		Requirements: []config.Requirement{
			{Library: strptr("template.envoy:2.0-entrypoint-application")},
			{Library: strptr("template.envoy:2.0-entrypoint-main")},
			{Library: strptr("template.envoy:2.0-entrypoint-authz")},
			{Library: strptr("template.envoy:2.0-entrypoint-log")},
			{Library: strptr("template.envoy:2.0-conflicts")},
		},
	},
	{
		Name: "template.kuma:1.0",
		Requirements: []config.Requirement{
			{Library: strptr("template.envoy:2.0-entrypoint-application")},
			{Library: strptr("template.envoy:2.0-entrypoint-main")},
			{Library: strptr("template.envoy:2.0-entrypoint-authz")},
			{Library: strptr("template.envoy:2.0-entrypoint-log")},
			{Library: strptr("template.envoy:2.0-conflicts")},
		},
	},
	{
		Name: "template.kong-gateway:1.0",
		Requirements: []config.Requirement{
			{Library: strptr("template.kong-gateway:1.0-entrypoint-main")},
			{Library: strptr("template.kong-gateway:1.0-conflicts")},
		},
	},
	{
		Name: "kubernetes:v2",
		Requirements: []config.Requirement{
			{Library: strptr("kubernetes:v2-entrypoint-validating")},
			{Library: strptr("kubernetes:v2-entrypoint-mutating")},
			{Library: strptr("kubernetes:v2-entrypoint-log")},
			{Library: strptr("kubernetes:v2-conflicts")},
			{Library: strptr("kubernetes:v2-library")},
		},
	},
	{
		Name: "template.terraform:2.0",
		Requirements: []config.Requirement{
			{Library: strptr("template.terraform:2.0-entrypoint-main")},
			{Library: strptr("template.terraform:2.0-conflicts")},
			{Library: strptr("template.terraform:2.0-library")},
		},
	},
}

func getSystemTypeLib(t string) *config.Library {
	for _, l := range systemTypeLibraries {
		if l.Name == t {
			return l
		}
	}
	return nil
}

var baseLibraries = []*config.Library{
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
		Name:    "template.envoy:2.0-entrypoint-application",
		Builtin: strptr("envoy-v2.0/application"),
	},
	{
		Name:    "template.envoy:2.0-entrypoint-main",
		Builtin: strptr("envoy-v2.0/main"),
	},
	{
		Name:    "template.envoy:2.0-entrypoint-authz",
		Builtin: strptr("envoy-v2.0/authz"),
	},
	{
		Name:    "template.envoy:2.0-entrypoint-log",
		Builtin: strptr("envoy-v2.0/log"),
	},
	{
		Name:    "template.envoy:2.0-conflicts",
		Builtin: strptr("envoy-v2.0/conflicts"),
	},
	{
		Name:    "template.kong-gateway:1.0-entrypoint-main",
		Builtin: strptr("kong-gateway-v1/main"),
	},
	{
		Name:    "template.kong-gateway:1.0-conflicts",
		Builtin: strptr("kong-gateway-v1/conflicts"),
	},
	{
		Name:    "kubernetes:v2-entrypoint-validating",
		Builtin: strptr("kubernetes-v2/validating"),
	},
	{
		Name:    "kubernetes:v2-entrypoint-mutating",
		Builtin: strptr("kubernetes-v2/mutating"),
	},
	{
		Name:    "kubernetes:v2-entrypoint-log",
		Builtin: strptr("kubernetes-v2/log"),
	},
	{
		Name:    "kubernetes:v2-conflicts",
		Builtin: strptr("kubernetes-v2/conflicts"),
	},
	{
		Name:    "kubernetes:v2-library",
		Builtin: strptr("kubernetes-v2/library"),
	},
	{
		Name:    "template.terraform:2.0-entrypoint-main",
		Builtin: strptr("terraform-v2.0/main"),
	},
	{
		Name:    "template.terraform:2.0-conflicts",
		Builtin: strptr("terraform-v2.0/conflicts"),
	},
	{
		Name:    "template.terraform:2.0-library",
		Builtin: strptr("terraform-v2.0/library"),
	},
	{
		Name:    "match-v1",
		Builtin: strptr("match-v1"),
	},
}

var baseLibFiles = func() map[string]map[string]string {
	result := make(map[string]map[string]string)
	for _, bi := range baseLibraries {
		result[bi.Name] = make(map[string]string)
		fs.WalkDir(libraries.FS, *bi.Builtin, func(file string, fi fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}
			bs, err := libraries.FS.ReadFile(file)
			if err != nil {
				return err
			}
			path := strings.TrimPrefix(file, *bi.Builtin)
			result[bi.Name][path] = string(bs)
			return nil
		})
	}
	return result
}()

func getBaseLib(r config.Requirement) *config.Library {
	for _, l := range baseLibraries {
		if l.Name == *r.Library {
			return l
		}
	}
	return nil
}

var baseLibPackageIndex = func() map[string]*libraryPackageIndex {
	result := map[string]*libraryPackageIndex{}
	for _, lib := range systemTypeLibraries {
		for _, r := range lib.Requirements {
			bi := getBaseLib(r)
			if bi == nil {
				panic(fmt.Sprintf("%v was not found", *r.Library))
			}
			err := fs.WalkDir(libraries.FS, *bi.Builtin, func(file string, fi fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if fi.IsDir() {
					return nil
				}
				if filepath.Ext(file) != ".rego" {
					return nil
				}
				bs, err := libraries.FS.ReadFile(file)
				if err != nil {
					return err
				}
				module, err := ast.ParseModule(file, string(bs))
				if err != nil {
					return err
				}
				ptr, err := module.Package.Path.Ptr()
				if err != nil {
					return err
				}
				index, ok := result[lib.Name]
				if !ok {
					index = newLibraryPackageIndex()
					result[lib.Name] = index
				}
				index.Add(ptr, bi.Name)
				return nil
			})
			if err != nil {
				panic(err)
			}
		}
	}
	return result
}()

type Options struct {
	Token       string
	URL         string
	SystemId    string
	Prune       bool
	Datasources bool
	FilesPath   string
	Logging     logging.Config
	Output      io.Writer
}

func init() {

	var params Options

	params.Token = os.Getenv("STYRA_TOKEN")

	migrate := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate configuration and policies from Styra",
		Run: func(cmd *cobra.Command, args []string) {
			params.Output = os.Stdout

			if err := Run(params); err != nil {
				log.Fatal(err.Error())
			}
		},
	}

	migrate.Flags().StringVarP(&params.URL, "url", "u", "", "Styra tenant URL (e.g., https://expo.styra.com)")
	migrate.Flags().StringVarP(&params.SystemId, "system-id", "", "", "Scope migraton to a specific system (id)")
	migrate.Flags().BoolVarP(&params.Prune, "prune", "", false, "Prune unused resources")
	migrate.Flags().BoolVarP(&params.Datasources, "datasources", "", false, "Copy datasource content")
	migrate.Flags().StringVarP(&params.FilesPath, "files", "", "files", "Path to write the non-git stored files to (default: files/)")
	logging.VarP(migrate, &params.Logging)

	cmd.RootCommand.AddCommand(
		migrate,
	)
}

func Run(params Options) error {
	log = logging.NewLogger(params.Logging)

	if params.URL == "" {
		return errors.New("please set Styra DAS URL with -u flag (e.g., https://example.styra.com)")
	}

	if params.Token == "" {
		return errors.New("please set STYRA_TOKEN environment variable to token with WorkspaceViewer permission")
	}

	c := das.Client{
		URL:    params.URL,
		Token:  params.Token,
		Client: http.DefaultClient,
	}

	output := config.Root{
		Systems:   map[string]*config.System{},
		Secrets:   map[string]*config.Secret{},
		Libraries: map[string]*config.Library{},
		Stacks:    map[string]*config.Stack{},
	}

	output.Metadata.ExportedFrom = params.URL
	output.Metadata.ExportedAt = time.Now().UTC().Format(time.RFC3339)

	state, err := fetchDASState(&c, dasFetchOptions{SystemId: params.SystemId})
	if err != nil {
		return err
	}

	for _, library := range state.LibrariesById {
		lc, secret, err := migrateV1Library(&c, state, library)
		if err != nil {
			return err
		}

		output.Libraries[lc.Name] = lc
		if secret != nil {
			output.Secrets[secret.Name] = secret
		}
	}

	for _, bi := range systemTypeLibraries {
		output.Libraries[bi.Name] = bi
	}

	for _, bi := range baseLibraries {
		output.Libraries[bi.Name] = bi
	}

	for _, system := range state.SystemsById {
		sc, secret, err := migrateV1System(&c, state, system, params.Datasources)
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

	if params.Prune {
		stacks, libraries, secrets := pruneConfig(&output)
		for _, stack := range stacks {
			log.Infof("Removed unused stack %q", stack.Name)
		}
		for _, lib := range libraries {
			log.Infof("Removed unused library %q", lib.Name)
		}
		for _, s := range secrets {
			log.Infof("Removed unused secret %q", s.Name)
		}
	}

	log.Info("Finished downloading resources from DAS. Printing migration configuration.")

	bs, err := yaml.Marshal(output)
	if err != nil {
		return err
	}

	fmt.Fprintln(params.Output, string(bs))

	v1SystemsByName := map[string]*das.V1System{}
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
			log.Infof("System %q has missing stacks %v", system.Name, missing)
		}
		if extra.Len() > 0 {
			log.Infof("System %q has extra stacks %v", system.Name, extra)
		}
	}

	files := make(map[string]string)

	for _, system := range output.Systems {
		for path, content := range system.Files() {
			files[filepath.Join(append([]string{"systems", system.Name}, filepath.SplitList(path)...)...)] = content
		}
	}

	for _, library := range output.Libraries {
		for path, content := range library.Files() {
			files[filepath.Join(append([]string{"libraries", library.Name}, filepath.SplitList(path)...)...)] = content
		}
	}

	if len(files) > 0 && params.FilesPath != "" {
		root := params.FilesPath

		log.Infof("Found %d files for systems and libraries. Writing them to disk under %s.", len(files), root)

		for path, content := range files {
			if err := os.MkdirAll(filepath.Join(root, filepath.Dir(path)), 0755); err != nil {
				return err
			}

			if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0644); err != nil {
				return err
			}
		}
	}

	return nil
}

func migrateV1Library(_ *das.Client, state *dasState, v1 *das.V1Library) (*config.Library, *config.Secret, error) {

	library, secret, err := mapV1LibraryToLibraryAndSecretConfig(v1)
	if err != nil {
		return nil, nil, err
	}

	// NOTE(tsandall): we don't support a mix of git-backed and non-git backed
	// files in libraries like we do for systems right now; if git config exists
	// then stop
	if library.Git.Repo != "" {
		return library, secret, nil
	}

	policies := state.LibraryPolicies[v1.Id]

	for _, p := range policies {
		for file, str := range p.Modules {
			library.SetEmbeddedFile(p.Package+"/"+file, str)
		}
	}

	return library, secret, nil
}

func mapV1LibraryToLibraryAndSecretConfig(v1 *das.V1Library) (*config.Library, *config.Secret, error) {

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

func migrateV1System(client *das.Client, state *dasState, v1 *das.V1System, datasources bool) (*config.System, *config.Secret, error) {

	system, secret, err := mapV1SystemToSystemAndSecretConfig(client, v1)
	if err != nil {
		return nil, nil, err
	}

	log.Infof("Fetching git roots and labels for system %q", v1.Name)

	resp, err := client.JSON("v1/systems/" + v1.Id + "/bundles")
	if err != nil {
		return nil, nil, err
	}

	bundles := []*das.V1Bundle{}
	if err := resp.Decode(&bundles); err != nil {
		return nil, nil, err
	}

	var gitRoots []string
	if len(bundles) > 0 {
		for i := range bundles[0].SBOM.Origins {
			gitRoots = append(gitRoots, bundles[0].SBOM.Origins[i].Roots...)
		}
	}

	policies := state.SystemPolicies[v1.Id]
	var files map[string]string
	files, system.Requirements = migrateV1Policies(v1.Type, "systems/"+v1.Id+"/", policies, gitRoots)
	system.SetEmbeddedFiles(files)

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

	if datasources {
		log.Infof("Fetching datasources for system %q", v1.Name)
		for _, ref := range v1.Datasources {
			resp, err := client.JSON("v1/datasources/" + ref.Id)
			if err != nil {
				return nil, nil, err
			}

			var ds das.V1Datasource
			if err := resp.Decode(&ds); err != nil {
				return nil, nil, err
			}

			if ds.Category == "rest" && ds.Type == "push" {
				files, err := migrateV1PushDatasource(client, "systems/"+v1.Id+"/", ds.Id)
				if err != nil {
					return nil, nil, err
				}
				for path, content := range files {
					system.SetEmbeddedFile(path, content)
				}
			} else {
				log.Infof("Unsupported datasource category/type: %v/%v", ds.Category, ds.Type)
			}
		}
	}

	return system, secret, nil
}

func mapV1SystemToSystemAndSecretConfig(_ *das.Client, v1 *das.V1System) (*config.System, *config.Secret, error) {
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

func migrateV1Policies(typeName string, nsPrefix string, policies []*das.V1Policy, gitRoots []string) (config.Files, []config.Requirement) {

	typeLib := getSystemTypeLib(typeName)
	excludeLibs := make(map[string]struct{})
	var files config.Files
	var requirements []config.Requirement

	for _, p := range policies {
		pkg := strings.TrimPrefix(p.Package, nsPrefix)

		if rootsPrefix(gitRoots, pkg) {
			if typeLib != nil {
				// If type lib provided file is Git backed then add it to the
				// exclude list automatically. We assume the user has taken
				// ownership of it.
				baseLibs := baseLibPackageIndex[typeLib.Name].Lookup(pkg)
				for name := range baseLibs {
					excludeLibs[name] = struct{}{}
				}
			}
		} else {
			modules := make(map[string]string)
			for path, str := range p.Modules {
				path = strings.TrimPrefix(pkg, "/") + "/" + path
				if !stringSliceContains(gitRoots, path) {
					modules[path] = str
				}
			}

			if typeLib != nil {
				// If the type lib provided file is non-Git backed then check if the
				// file content is the same. If not, add it to the exclude list because
				// the user has changed it.
				baseLibs := baseLibPackageIndex[typeLib.Name].Lookup(pkg)
				libFiles := make(map[string]string)
				for name := range baseLibs {
					for path, str := range baseLibFiles[name] {
						libFiles[strings.TrimPrefix(path, "/")] = str
					}
				}

				// If the system files for this package are the same as the type lib then skip
				// skip them (a requirement will be added below). If they differ then add the base lib
				// to the exclude list and fallthrough to below to add the files.
				if reflect.DeepEqual(modules, libFiles) {
					continue
				}

				for name := range baseLibs {
					excludeLibs[name] = struct{}{}
				}
			}

			for path, str := range modules {
				if files == nil {
					files = make(config.Files)
				}
				files[path] = str
			}
		}
	}

	if typeLib != nil {
		if len(excludeLibs) == 0 {
			requirements = append(requirements, typeLib.Requirement())
		} else {
			for _, r := range typeLib.Requirements {
				if _, ok := excludeLibs[*r.Library]; !ok {
					requirements = append(requirements, r)
				}
			}
		}
	}

	return files, requirements
}

func migrateV1PushDatasource(c *das.Client, nsPrefix string, id string) (config.Files, error) {
	resp, err := c.JSON("v1/data/" + id)
	if err != nil {
		return nil, err
	}

	result := make(config.Files)
	result[strings.TrimPrefix(id, nsPrefix)+"/data.json"] = string(resp.Result)
	return result, nil
}

func migrateV1Stack(_ *das.Client, state *dasState, v1 *das.V1Stack) (*config.Stack, *config.Library, *config.Secret, error) {

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
		for file, str := range policies[i].Modules {
			library.SetEmbeddedFile(policies[i].Package+"/"+file, str)
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

func migrateDependencies(_ *das.Client, state *dasState, output *config.Root) error {

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

func getRequirementsForPolicies(policies []*das.V1Policy, index *libraryPackageIndex, ignore string) ([]config.Requirement, error) {
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

func pruneConfig(root *config.Root) ([]*config.Stack, []*config.Library, []*config.Secret) {

	var removedStacks []*config.Stack
	var removedLibraries []*config.Library
	var removedSecrets []*config.Secret

	for _, stack := range root.Stacks {
		var found bool
		for _, system := range root.Systems {
			if stack.Selector.Matches(system.Labels) {
				found = true
			}
		}
		if !found {
			delete(root.Stacks, stack.Name)
			removedStacks = append(removedStacks, stack)
		}
	}

	g := make(graph)

	for _, system := range root.Systems {
		for _, r := range system.Requirements {
			if r.Library != nil {
				g[*r.Library] = append(g[*r.Library], node{name: system.Name})
			}
		}
	}

	for _, stack := range root.Stacks {
		for _, r := range stack.Requirements {
			if r.Library != nil {
				g[*r.Library] = append(g[*r.Library], node{name: stack.Name})
			}
		}
	}

	for _, lib := range root.Libraries {
		for _, r := range lib.Requirements {
			if r.Library != nil {
				g[*r.Library] = append(g[*r.Library], node{name: lib.Name, lib: true})
			}
		}
	}

	for _, lib := range root.Libraries {
		var found bool
		g.DFS(lib.Name, func(n node) {
			if !n.lib {
				found = true
			}
		})
		if !found {
			delete(root.Libraries, lib.Name)
			removedLibraries = append(removedLibraries, lib)
		}
	}

	credentials := make(map[string]struct{})
	for _, system := range root.Systems {
		if system.Git.Credentials != nil {
			credentials[system.Git.Credentials.Name] = struct{}{}
		}
	}
	for _, lib := range root.Libraries {
		if lib.Git.Credentials != nil {
			credentials[lib.Git.Credentials.Name] = struct{}{}
		}
	}

	for _, s := range root.Secrets {
		if _, ok := credentials[s.Name]; !ok {
			delete(root.Secrets, s.Name)
			removedSecrets = append(removedSecrets, s)
		}
	}

	return removedStacks, removedLibraries, removedSecrets
}

type node struct {
	name string
	lib  bool
}

type graph map[string][]node

func (g graph) DFS(n string, iter func(node)) {
	g.dfs(n, iter, make(map[string]struct{}))
}

func (g graph) dfs(n string, iter func(node), visited map[string]struct{}) {
	if _, ok := visited[n]; ok {
		return
	}
	edges, ok := g[n]
	if !ok {
		return
	}
	visited[n] = struct{}{}
	for _, node := range edges {
		iter(node)
		g.dfs(node.name, iter, visited)
	}
}

type dasState struct {
	DatasourcesById map[string]*das.V1Datasource
	SystemsById     map[string]*das.V1System
	SystemPolicies  map[string][]*das.V1Policy
	StacksById      map[string]*das.V1Stack
	StackPolicies   map[string][]*das.V1Policy
	LibrariesById   map[string]*das.V1Library
	LibraryPolicies map[string][]*das.V1Policy
}

type dasFetchOptions struct {
	SystemId string
}

func fetchDASState(c *das.Client, opts dasFetchOptions) (*dasState, error) {
	state := dasState{}

	var systems []*das.V1System

	if opts.SystemId == "" {
		log.Info("Fetching v1/systems")
		resp, err := c.JSON("v1/systems")
		if err != nil {
			return nil, err
		}

		err = resp.Decode(&systems)
		if err != nil {
			return nil, err
		}
	} else {
		log.Info("Fetching v1/systems/" + opts.SystemId)
		resp, err := c.JSON("v1/systems/" + opts.SystemId)
		if err != nil {
			return nil, err
		}

		var x das.V1System
		if err := resp.Decode(&x); err != nil {
			return nil, err
		}

		systems = append(systems, &x)
	}

	log.Info("Fetching v1/libraries")
	resp, err := c.JSON("v1/libraries")
	if err != nil {
		return nil, err
	}

	var libraries []*das.V1Library
	err = resp.Decode(&libraries)
	if err != nil {
		return nil, err
	}

	log.Info("Fetching v1/stacks")
	resp, err = c.JSON("v1/stacks")
	if err != nil {
		return nil, err
	}

	var stacks []*das.V1Stack
	err = resp.Decode(&stacks)
	if err != nil {
		return nil, err
	}

	state.SystemsById = map[string]*das.V1System{}
	for _, s := range systems {
		state.SystemsById[s.Id] = s
	}

	state.StacksById = map[string]*das.V1Stack{}
	for _, s := range stacks {
		state.StacksById[s.Id] = s
	}

	state.LibrariesById = map[string]*das.V1Library{}
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

func fetchSystemPolicies(c *das.Client, state *dasState) error {
	ch := make(chan *das.V1System)
	var wg sync.WaitGroup
	var mu sync.Mutex

	state.SystemPolicies = map[string][]*das.V1Policy{}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			for s := range ch {
				log.Infof("Fetching %d policies for system %q", len(s.Policies), s.Name)
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

func fetchStackPolicies(c *das.Client, state *dasState) error {
	ch := make(chan *das.V1Stack)
	var wg sync.WaitGroup
	var mu sync.Mutex

	state.StackPolicies = map[string][]*das.V1Policy{}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			for s := range ch {
				log.Infof("Fetching %d policies for stack %q", len(s.Policies), s.Name)
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

func fetchLibraryPolicies(c *das.Client, state *dasState) error {
	ch := make(chan *das.V1Library)
	var wg sync.WaitGroup
	var mu sync.Mutex

	state.LibraryPolicies = map[string][]*das.V1Policy{}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			for l := range ch {

				// List libraries differs from systems/stacks. Result does not
				// have policies on it. Need to fetch each library individually.
				resp, err := c.JSON("v1/libraries/"+l.Id, das.Params{
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

				log.Infof("Fetching %d policies for library %q", len(l.Policies), l.Id)
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

func fetchPolicies(c *das.Client, refs []das.V1PoliciesRef) ([]*das.V1Policy, error) {
	var result []*das.V1Policy
	for _, ref := range refs {
		resp, err := c.JSON("v1/policies/" + ref.Id)
		if err != nil {
			if dErr, ok := err.(das.Error); ok && dErr.StatusCode == http.StatusNotFound {
				log.Infof("Non-existent policy reference: %v", ref.Id)
				continue
			}
			return nil, err
		}
		var p das.V1Policy
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
	keys := strings.Split(strings.Trim(path, "/"), "/")
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

func rootsPrefix(roots []string, path string) bool {
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	for _, r := range roots {
		rParts := strings.Split(strings.Trim(r, "/"), "/")
		if stringSlicePrefix(rParts, pathParts) {
			return true
		}
	}
	return false
}

func stringSlicePrefix(prefix []string, s []string) bool {
	if len(prefix) > len(s) {
		return false
	}
	for i := range prefix {
		if prefix[i] != s[i] {
			return false
		}
	}
	return true
}

func stringSliceContains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func strptr(s string) *string { return &s }
