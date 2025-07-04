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
	"github.com/styrainc/lighthouse/cmd"
	"github.com/styrainc/lighthouse/cmd/internal/das"
	"github.com/styrainc/lighthouse/internal/config"
	"github.com/styrainc/lighthouse/internal/logging"
	"github.com/styrainc/lighthouse/libraries"
	"gopkg.in/yaml.v3"
)

var log *logging.Logger

var allocatedNames = make(map[string]int)

func assignSafeName(basename string) string {
	count := allocatedNames[basename]
	allocatedNames[basename] = count + 1
	if count == 0 {
		return basename
	}

	return fmt.Sprintf("%s-%d", basename, count)
}

var systemTypeLibraries = []*config.Source{
	{
		Name: "template.envoy:2.1",
		Requirements: []config.Requirement{
			{Source: strptr("template.envoy:2.1-entrypoint-application")},
			{Source: strptr("template.envoy:2.1-entrypoint-main")},
			{Source: strptr("template.envoy:2.1-entrypoint-authz")},
			{Source: strptr("template.envoy:2.1-entrypoint-log")},
			{Source: strptr("template.envoy:2.1-conflicts")},
		},
	},
	{
		Name: "template.envoy:2.0",
		Requirements: []config.Requirement{
			{Source: strptr("template.envoy:2.0-entrypoint-application")},
			{Source: strptr("template.envoy:2.0-entrypoint-main")},
			{Source: strptr("template.envoy:2.0-entrypoint-authz")},
			{Source: strptr("template.envoy:2.0-entrypoint-log")},
			{Source: strptr("template.envoy:2.0-conflicts")},
		},
	},
	{
		Name: "template.istio:1.0",
		Requirements: []config.Requirement{
			{Source: strptr("template.envoy:2.0-entrypoint-application")},
			{Source: strptr("template.envoy:2.0-entrypoint-main")},
			{Source: strptr("template.envoy:2.0-entrypoint-authz")},
			{Source: strptr("template.envoy:2.0-entrypoint-log")},
			{Source: strptr("template.envoy:2.0-conflicts")},
		},
	},
	{
		Name: "template.kuma:1.0",
		Requirements: []config.Requirement{
			{Source: strptr("template.envoy:2.0-entrypoint-application")},
			{Source: strptr("template.envoy:2.0-entrypoint-main")},
			{Source: strptr("template.envoy:2.0-entrypoint-authz")},
			{Source: strptr("template.envoy:2.0-entrypoint-log")},
			{Source: strptr("template.envoy:2.0-conflicts")},
		},
	},
	{
		Name: "template.kong-gateway:1.0",
		Requirements: []config.Requirement{
			{Source: strptr("template.kong-gateway:1.0-entrypoint-main")},
			{Source: strptr("template.kong-gateway:1.0-conflicts")},
		},
	},
	{
		Name: "kubernetes:v2",
		Requirements: []config.Requirement{
			{Source: strptr("kubernetes:v2-entrypoint-validating")},
			{Source: strptr("kubernetes:v2-entrypoint-mutating")},
			{Source: strptr("kubernetes:v2-entrypoint-log")},
			{Source: strptr("kubernetes:v2-conflicts")},
			{Source: strptr("kubernetes:v2-library")},
		},
	},
	{
		Name: "template.terraform:2.0",
		Requirements: []config.Requirement{
			{Source: strptr("template.terraform:2.0-entrypoint-main")},
			{Source: strptr("template.terraform:2.0-conflicts")},
			{Source: strptr("template.terraform:2.0-library")},
		},
	},
	{
		Name: "template.entitlements:1.0",
		Requirements: []config.Requirement{
			{Source: strptr("template.entitlements:1.0-entrypoint-main")},
			{Source: strptr("template.entitlements:1.0-object")},
			{Source: strptr("template.entitlements:1.0-completions")},
			{Source: strptr("template.entitlements:1.0-conflicts")},
			{Source: strptr("template.entitlements:1.0-transform")},
			{Source: strptr("template.entitlements:1.0-library")},
		},
	},
}

func getSystemTypeLib(t string) *config.Source {
	for _, l := range systemTypeLibraries {
		if l.Name == t {
			return l
		}
	}
	return nil
}

var stackTypeLibraries = map[string]*config.Source{
	"template.envoy:2.1": {
		Name: "template.envoy:2.1-stack",
		Requirements: []config.Requirement{
			{Source: strptr("match-v1")},
		},
	},
	"template.envoy:2.0": {
		Name: "template.envoy:2.0-stack",
		Requirements: []config.Requirement{
			{Source: strptr("match-v1")},
		},
	},
	"template.istio:1.0": {
		Name: "template.istio:1.0-stack",
		Requirements: []config.Requirement{
			{Source: strptr("match-v1")},
		},
	},
	"template.kuma:1.0": {
		Name: "template.kuma:1.0-stack",
		Requirements: []config.Requirement{
			{Source: strptr("match-v1")},
		},
	},
	"template.kong-gateway:1.0": {
		Name: "template.kong-gateway:1.0-stack",
		Requirements: []config.Requirement{
			{Source: strptr("match-v1")},
		},
	},
	"kubernetes:v2": {
		Name: "kubernetes:v2-stack",
		Requirements: []config.Requirement{
			{Source: strptr("kubernetes:v2-library")},
			{Source: strptr("match-v1")},
		},
	},
	"template.terraform:2.0": {
		Name: "template.terraform:2.0-stack",
		Requirements: []config.Requirement{
			{Source: strptr("template.terraform:2.0-library")},
			{Source: strptr("match-v1")},
		},
	},
	"template.entitlements:1.0": {
		Name: "template.entitlements:1.0-stack",
		Requirements: []config.Requirement{
			{Source: strptr("template.entitlements:1.0-library")},
			{Source: strptr("match-v1")},
		},
	},
}

var baseLibraries = []*config.Source{
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
		Name:    "template.entitlements:1.0-completions",
		Builtin: strptr("entitlements-v1/completions"),
	},
	{
		Name:    "template.entitlements:1.0-transform",
		Builtin: strptr("entitlements-v1/transform"),
	},
	{
		Name:    "template.entitlements:1.0-object",
		Builtin: strptr("entitlements-v1/object"),
	},
	{
		Name:    "template.entitlements:1.0-library",
		Builtin: strptr("entitlements-v1/library"),
	},
	{
		Name:    "template.entitlements:1.0-conflicts",
		Builtin: strptr("entitlements-v1/conflicts"),
	},
	{
		Name:    "template.entitlements:1.0-entrypoint-main",
		Builtin: strptr("entitlements-v1/main"),
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

func getBaseLib(r config.Requirement) *config.Source {
	for _, l := range baseLibraries {
		if l.Name == *r.Source {
			return l
		}
	}
	return nil
}

var baseLibPackageIndex = func() map[string]*libraryPackageIndex {
	result := map[string]*libraryPackageIndex{}
	addReqs := func(lib *config.Source) {
		for _, r := range lib.Requirements {
			bi := getBaseLib(r)
			if bi == nil {
				panic(fmt.Sprintf("%v was not found", *r.Source))
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
	for _, lib := range systemTypeLibraries {
		addReqs(lib)
	}
	for _, lib := range stackTypeLibraries {
		addReqs(lib)
	}
	return result
}()

type Options struct {
	Token          string
	URL            string
	Headers        []string
	SystemId       string
	Prune          bool
	Datasources    bool
	FilesPath      string
	EmbedFiles     bool
	Logging        logging.Config
	Output         io.Writer
	OutputDir      string
	S3BucketName   string
	S3BucketRegion string
}

func init() {

	var params Options

	var stdout bool
	params.Token = os.Getenv("STYRA_TOKEN")

	migrate := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate configuration and policies from Styra",
		PreRun: func(cmd *cobra.Command, args []string) {
			if !cmd.Flags().Changed("prune") && params.SystemId != "" {
				params.Prune = true
			}
			if !cmd.Flags().Changed("output-dir") {
				params.OutputDir = "config.d"
				if params.SystemId != "" {
					params.OutputDir = filepath.Join(params.OutputDir, params.SystemId)
				}
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			if stdout {
				params.Output = os.Stdout
			}
			if err := Run(params); err != nil {
				log.Fatal(err.Error())
			}
		},
	}

	migrate.Flags().StringVarP(&params.URL, "url", "u", "", "Styra tenant URL (e.g., https://expo.styra.com)")
	migrate.Flags().StringSliceVarP(&params.Headers, "header", "", nil, "Set additional HTTP headers for requests to Styra API")
	migrate.Flags().StringVarP(&params.SystemId, "system-id", "", "", "Scope migraton to a specific system (id)")
	migrate.Flags().BoolVarP(&params.Prune, "prune", "", false, "Prune unused resources")
	migrate.Flags().BoolVarP(&params.Datasources, "datasources", "", false, "Copy datasource content")
	migrate.Flags().StringVarP(&params.FilesPath, "files", "", "files", "Path to write the non-git stored files to")
	migrate.Flags().BoolVarP(&params.EmbedFiles, "embed-files", "", false, "Embed non-git stored files into output configuration")
	migrate.Flags().BoolVarP(&stdout, "stdout", "", false, "Write configuration to stdout")
	migrate.Flags().StringVarP(&params.OutputDir, "output-dir", "o", "", "Directory to output configuration files to (default \"config.d[/<system-id>]\")")
	migrate.Flags().StringVarP(&params.S3BucketName, "s3-bucket-name", "", "BUCKET_NAME", "Set placeholder AWS S3 bucket name for object storage")
	migrate.Flags().StringVarP(&params.S3BucketRegion, "s3-bucket-region", "", "BUCKET_REGION", "Set placeholder AWS S3 bucket region for object storage")
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
		log.Info("STYRA_TOKEN is not set, make sure to grant token WorkspaceViewer role")
	}

	c := das.Client{
		URL:     params.URL,
		Headers: params.Headers,
		Token:   params.Token,
		Client:  http.DefaultClient,
	}

	output := config.Root{
		Bundles: map[string]*config.Bundle{},
		Secrets: map[string]*config.Secret{},
		Sources: map[string]*config.Source{},
		Stacks:  map[string]*config.Stack{},
	}

	output.Metadata.ExportedFrom = params.URL
	output.Metadata.ExportedAt = time.Now().UTC().Format(time.RFC3339)

	state, err := fetchDASState(&c, dasFetchOptions{SystemId: params.SystemId})
	if err != nil {
		return err
	}

	for _, library := range state.LibrariesById {
		sc, secrets, err := migrateV1Library(&c, state, library, params.Datasources)
		if err != nil {
			return err
		}

		output.Sources[sc.Name] = sc
		for _, s := range secrets {
			output.Secrets[s.Name] = s
		}
	}

	for _, bi := range systemTypeLibraries {
		output.Sources[bi.Name] = bi
	}

	for _, bi := range stackTypeLibraries {
		output.Sources[bi.Name] = bi
	}

	for _, bi := range baseLibraries {
		output.Sources[bi.Name] = bi
	}

	for _, system := range state.SystemsById {
		b, src, secrets, err := migrateV1System(&c, state, system, params.Datasources)
		if err != nil {
			return err
		}

		output.Sources[src.Name] = src
		output.Bundles[b.Name] = b

		for _, s := range secrets {
			output.Secrets[s.Name] = s
		}
	}

	for _, stack := range state.StacksById {
		sc, src, secrets, err := migrateV1Stack(&c, state, stack, params.Datasources)
		if err != nil {
			return err
		}

		output.Stacks[sc.Name] = sc
		output.Sources[src.Name] = src

		for _, s := range secrets {
			output.Secrets[s.Name] = s
		}

		if _, ok := sc.Selector.Get(staticStackMatchLabelKey); ok {
			for _, systemId := range stack.MatchingSystems {
				s, ok := state.SystemsById[systemId]
				if !ok {
					if params.SystemId == systemId {
						return fmt.Errorf("unexpected error: missing state for system %q", systemId)
					}
					if params.SystemId == "" {
						log.Warnf("Stack %q matches non-existent system %v", stack.Name, systemId)
					}
					continue
				}
				log.Warnf("Stack %q selector logic cannot be automatically translated. Review logic and configure bundle labels and stack selector manually.", stack.Name)
				output.Bundles[s.Name].Labels[staticStackMatchLabelKey] = sc.Name
			}
		}
	}

	if err := migrateDependencies(&c, state, &output); err != nil {
		return err
	}

	if params.Prune {
		stacks, sources, secrets := pruneConfig(&output)
		sort.Slice(stacks, func(i, j int) bool {
			return stacks[i].Name < stacks[j].Name
		})
		sort.Slice(sources, func(i, j int) bool {
			return sources[i].Name < sources[j].Name
		})
		sort.Slice(secrets, func(i, j int) bool {
			return secrets[i].Name < secrets[j].Name
		})
		for _, stack := range stacks {
			log.Infof("Removed unused stack %q", stack.Name)
		}
		for _, lib := range sources {
			log.Infof("Removed unused source %q", lib.Name)
		}
		for _, s := range secrets {
			log.Infof("Removed unused secret %q", s.Name)
		}
	}

	files := make(map[string]string)

	for _, src := range output.Sources {
		srcFiles, err := src.Files()
		if err != nil {
			return err
		}

		for path, content := range srcFiles {
			files[filepath.Join(append([]string{"sources", src.Name}, filepath.SplitList(path)...)...)] = content

			if !params.EmbedFiles && params.FilesPath != "" {
				src.SetDirectory(filepath.Join(params.FilesPath, "sources", src.Name))
				src.SetPath(path)
			}
		}
		if !params.EmbedFiles {
			src.SetEmbeddedFiles(nil)
		}
	}

	if len(files) > 0 && params.FilesPath != "" {
		root := params.FilesPath

		rootAbs, err := filepath.Abs(root)
		if err != nil {
			return err
		}

		log.Infof("Found %d files for sources. Writing them to disk under %s", len(files), rootAbs)

		for path, content := range files {
			if err := os.MkdirAll(filepath.Join(root, filepath.Dir(path)), 0755); err != nil {
				return err
			}

			if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0644); err != nil {
				return err
			}
		}
	}

	if len(params.S3BucketName) > 0 {
		for name := range output.Bundles {
			output.Bundles[name].ObjectStorage = config.ObjectStorage{
				AmazonS3: &config.AmazonS3{
					Bucket:      params.S3BucketName,
					Region:      params.S3BucketRegion,
					Key:         "bundles/" + name + "/bundle.tar.gz",
					Credentials: &config.SecretRef{Name: "storage-creds"},
				},
			}
		}
		if len(output.Bundles) > 0 {
			output.Secrets["storage-creds"] = &config.Secret{
				Name: "storage-creds",
				Value: map[string]interface{}{
					"type":              "aws_auth",
					"access_key_id":     "$AWS_ACCESS_KEY_ID",
					"secret_access_key": "$AWS_SECRET_ACCESS_KEY",
					"session_token":     "$AWS_SESSION_TOKEN",
				},
			}
		}
	}

	if params.Output != nil {

		log.Info("Finished downloading resources from DAS. Writing configuration to stdout")
		bs, err := yaml.Marshal(output)
		if err != nil {
			return err
		}

		fmt.Fprintln(params.Output, string(bs))
	} else {
		rootAbs, err := filepath.Abs(params.OutputDir)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(rootAbs, 0755); err != nil {
			return err
		}

		log.Infof("Finished downloading resources from DAS. Writing configuration files under %v", rootAbs)
		files, err := splitConfig(rootAbs, output)
		if err != nil {
			return err
		}
		for name, content := range files {
			if err := os.WriteFile(name, content, 0644); err != nil {
				return err
			}
		}
	}

	v1SystemsByName := map[string]*das.V1System{}
	for _, system := range state.SystemsById {
		v1SystemsByName[system.Name] = system
	}

	for _, system := range output.Bundles {
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

	return nil
}

func splitConfig(outputDir string, output config.Root) (map[string][]byte, error) {

	configs := make(map[string]config.Root)

	if len(output.Bundles) > 0 {
		configs["config-bundles.yaml"] = config.Root{Bundles: output.Bundles}
	}
	if len(output.Stacks) > 0 {
		configs["config-stacks.yaml"] = config.Root{Stacks: output.Stacks}
	}
	if len(output.Sources) > 0 {
		configs["config-sources.yaml"] = config.Root{Sources: output.Sources}
	}
	if len(output.Secrets) > 0 {
		configs["config-secrets.yaml"] = config.Root{Secrets: output.Secrets}
	}

	testFiles := make(map[string]*config.Source)
	for name, original := range output.Sources {
		files, err := original.Files()
		if err != nil {
			return nil, err
		}

		if len(files) > 0 {
			cpy := &config.Source{Name: name}
			cpy.SetEmbeddedFiles(files)
			testFiles[name] = cpy
			original.SetEmbeddedFiles(nil)
		}
	}

	if len(testFiles) > 0 {
		configs["test-files.yaml"] = config.Root{Sources: testFiles}
	}

	result := make(map[string][]byte)
	for name, root := range configs {
		root.Metadata = output.Metadata
		bs, err := yaml.Marshal(root)
		if err != nil {
			return nil, err
		}
		result[filepath.Join(outputDir, name)] = bs
	}

	return result, nil
}

func migrateV1Library(client *das.Client, state *dasState, v1 *das.V1Library, migrateDSContent bool) (*config.Source, []*config.Secret, error) {

	src, secrets, err := mapV1LibraryToSourceAndSecretConfig(client, v1, migrateDSContent)
	if err != nil {
		return nil, nil, err
	}

	// NOTE(tsandall): we don't support a mix of git-backed and non-git backed
	// files in libraries like we do for systems right now; if git config exists
	// then stop
	if src.Git.Repo != "" {
		return src, secrets, nil
	}

	policies := state.LibraryPolicies[v1.Id]

	for _, p := range policies {
		for file, str := range p.Modules {
			src.SetEmbeddedFile(p.Package+"/"+file, str)
		}
	}

	return src, secrets, nil
}

func mapV1LibraryToSourceAndSecretConfig(client *das.Client, v1 *das.V1Library, datasources bool) (*config.Source, []*config.Secret, error) {

	src := &config.Source{Name: assignSafeName(v1.Id)}
	var secrets []*config.Secret

	_, origin := getLibraryGitOrigin(v1)
	secret := migrateV1GitConfig(origin, src)
	if secret != nil {
		secrets = append(secrets, secret)
	}

	if src.Git.Repo != "" {
		src.Git.IncludedFiles = []string{"libraries/" + v1.Id + "/*"}
	}

	if len(v1.Datasources) > 0 {
		log.Infof("Fetching datasources for library %q", v1.Id)

		ds, files, dsSecrets, err := migrateV1Datasources(client, "", v1.Datasources, datasources)
		if err != nil {
			return nil, nil, err
		}

		secrets = append(secrets, dsSecrets...)
		src.Datasources = ds

		for _, fs := range files {
			for file, content := range fs {
				src.SetEmbeddedFile(file, content)
			}
		}
	}

	return src, secrets, nil
}

func getLibraryGitOrigin(v1 *das.V1Library) (bool, *das.V1GitRepoConfig) {
	if v1.SourceControl == nil {
		return false, nil
	}
	if v1.SourceControl.UseWorkspaceSettings && v1.SourceControl.Origin.URL != "" {
		return true, &v1.SourceControl.Origin
	}
	return false, &v1.SourceControl.LibraryOrigin
}

func migrateV1System(client *das.Client, state *dasState, v1 *das.V1System, migrateDSContent bool) (*config.Bundle, *config.Source, []*config.Secret, error) {

	var secrets []*config.Secret
	bundle, library, secret, err := mapV1SystemToBundleSourceAndSecretConfig(client, v1)
	if err != nil {
		return nil, nil, nil, err
	}

	if secret != nil {
		secrets = append(secrets, secret)
	}

	gitRoots, err := getSystemGitRoots(client, state.FeatureFlags.SBOM, v1)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get git roots for system %q: %w", v1.Name, err)
	}

	policies := state.SystemPolicies[v1.Id]
	var files map[string]string
	typeLib := getSystemTypeLib(v1.Type)
	files, library.Requirements = migrateV1Policies(typeLib, "systems/"+v1.Id+"/", policies, gitRoots)
	library.SetEmbeddedFiles(files)

	resp, err := client.JSON(fmt.Sprintf("v1/data/metadata/%v/labels", v1.Id))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to query labels for %q: %w", v1.Name, err)
	}

	if len(resp.Result) > 0 {
		var x struct {
			Labels config.Labels `json:"labels"`
		}
		if err := resp.Decode(&x); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decode labels for %q: %w", v1.Name, err)
		}
		bundle.Labels = x.Labels
		bundle.Labels["system-type"] = v1.Type // TODO(tsandall): remove template. prefix?
	}

	if len(v1.Datasources) > 0 {
		log.Infof("Fetching datasources for system %q", v1.Name)

		ds, files, dsSecrets, err := migrateV1Datasources(client, "systems/"+v1.Id+"/", v1.Datasources, migrateDSContent)
		if err != nil {
			return nil, nil, nil, err
		}

		for _, fs := range files {
			for file, content := range fs {
				library.SetEmbeddedFile(file, content)
			}
		}

		library.Datasources = ds
		secrets = append(secrets, dsSecrets...)
	}

	return bundle, library, secrets, nil
}

func migrateV1Datasources(client *das.Client, nsPrefix string, v1 []das.V1DatasourceRef, migrateDSContent bool) ([]config.Datasource, []config.Files, []*config.Secret, error) {

	var secrets []*config.Secret
	var dss []config.Datasource
	var files []config.Files

	for _, ref := range v1 {
		resp, err := client.JSON("v1/datasources/" + ref.Id)
		if err != nil {
			return nil, nil, nil, err
		}

		var ds das.V1Datasource
		if err := resp.Decode(&ds); err != nil {
			return nil, nil, nil, err
		}

		if ds.Category == "rest" && ds.Type == "push" {
			// ignore
		} else if ds.Category == "http" && ds.Type == "pull" {
			ds, secret, err := migrateV1HTTPPullDatasource(nsPrefix, &ds)
			if err != nil {
				return nil, nil, nil, err
			}
			if secret != nil {
				secrets = append(secrets, secret)
			}
			dss = append(dss, ds)
		} else {
			log.Warnf("%v/%v datasource configuration migration not supported yet", ds.Category, ds.Type)
		}

		if migrateDSContent {
			if ds.Category == "rest" && ds.Type == "push" {
				fs, err := migrateV1PushDatasource(client, nsPrefix, ds.Id)
				if err != nil {
					return nil, nil, nil, err
				}
				files = append(files, fs)
			} else {
				log.Warnf("%v/%v datasource content migration not supported yet", ds.Category, ds.Type)
			}
		}
	}

	return dss, files, secrets, nil
}

func migrateV1HTTPPullDatasource(nsPrefix string, v1 *das.V1Datasource) (config.Datasource, *config.Secret, error) {

	var ds config.Datasource
	ds.Name = v1.Id
	ds.Type = "http"
	ds.Path = strings.TrimPrefix(v1.Id, nsPrefix)
	ds.Config = make(map[string]interface{})
	ds.Config["url"] = v1.URL

	// TODO(tsandall): add header support (incl. secrets)

	return ds, nil, nil
}

func mapV1SystemToBundleSourceAndSecretConfig(_ *das.Client, v1 *das.V1System) (*config.Bundle, *config.Source, *config.Secret, error) {
	var bundle config.Bundle
	var src config.Source
	var secret *config.Secret

	bundle.Name = v1.Name
	src.Name = assignSafeName(v1.Name)
	bundle.Requirements = append(bundle.Requirements, config.Requirement{Source: strptr(src.Name)})

	if v1.SourceControl != nil {
		src.Git.Repo = v1.SourceControl.Origin.URL

		if v1.SourceControl.Origin.Commit != "" {
			src.Git.Commit = &v1.SourceControl.Origin.Commit
		} else if v1.SourceControl.Origin.Reference != "" {
			src.Git.Reference = &v1.SourceControl.Origin.Reference
		}

		if v1.SourceControl.Origin.Path != "" {
			src.Git.Path = &v1.SourceControl.Origin.Path
		}

		if v1.SourceControl.Origin.Credentials != "" {
			secret = &config.Secret{}
			secret.Name = v1.SourceControl.Origin.Credentials
			src.Git.Credentials = &config.SecretRef{Name: secret.Name}
		} else if v1.SourceControl.Origin.SSHCredentials.PrivateKey != "" {
			secret = &config.Secret{}
			secret.Name = v1.SourceControl.Origin.SSHCredentials.PrivateKey
			src.Git.Credentials = &config.SecretRef{Name: secret.Name}
		}
	}

	return &bundle, &src, secret, nil
}

func migrateV1Policies(typeLib *config.Source, nsPrefix string, policies []*das.V1Policy, gitRoots []string) (config.Files, []config.Requirement) {

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
				if _, ok := excludeLibs[*r.Source]; !ok {
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

const staticStackMatchLabelKey = "fixme-static-stack-match"

func migrateV1Stack(c *das.Client, state *dasState, v1 *das.V1Stack, migrateDSContent bool) (*config.Stack, *config.Source, []*config.Secret, error) {

	var stack config.Stack
	stack.Name = v1.Name

	src, secrets, err := mapV1StackToSourceAndSecretConfig(c, v1, migrateDSContent)
	if err != nil {
		return nil, nil, nil, err
	}

	stack.Requirements = append(stack.Requirements, config.Requirement{Source: &src.Name})

	gitRoots, err := getStackGitRoots(c, state.FeatureFlags.SBOM, v1)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get git roots for stack %q: %w", v1.Name, err)
	}

	policies := state.StackPolicies[v1.Id]
	var files config.Files
	files, src.Requirements = migrateV1Policies(stackTypeLibraries[v1.Type], "", policies, gitRoots)
	for path, content := range files {
		src.SetEmbeddedFile(path, content)
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

			stack.Selector, err = migrateV1Selector(v1, module)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to migrate selector for %q: %w", v1.Name, err)
			}

			return &stack, src, secrets, err
		}
	}

	return nil, nil, nil, fmt.Errorf("misisng selector policy for %q", v1.Name)
}

func mapV1StackToSourceAndSecretConfig(client *das.Client, v1 *das.V1Stack, migrateDSContent bool) (*config.Source, []*config.Secret, error) {

	src := &config.Source{Name: assignSafeName(v1.Name)}
	var secrets []*config.Secret

	if len(v1.Datasources) > 0 {
		log.Infof("Fetching datasources for stack %q", v1.Id)

		ds, files, dsSecrets, err := migrateV1Datasources(client, "", v1.Datasources, migrateDSContent)
		if err != nil {
			return nil, nil, err
		}

		secrets = append(secrets, dsSecrets...)
		src.Datasources = ds

		for _, fs := range files {
			for file, content := range fs {
				src.SetEmbeddedFile(file, content)
			}
		}
	}

	_, origin := getStackGitOrigin(v1)
	if origin == nil {
		return src, secrets, nil
	}

	if secret := migrateV1GitConfig(origin, src); secret != nil {
		secrets = append(secrets, secret)
	}

	if src.Git.Repo != "" {
		src.Git.IncludedFiles = []string{"stacks/" + v1.Id + "/*"}
	}

	return src, secrets, nil
}

func getStackGitOrigin(v1 *das.V1Stack) (bool, *das.V1GitRepoConfig) {
	if v1.SourceControl == nil {
		return false, nil
	}
	if v1.SourceControl.UseWorkspaceSettings && v1.SourceControl.Origin.URL != "" {
		return true, &v1.SourceControl.Origin
	}
	return false, &v1.SourceControl.StackOrigin
}

func migrateV1GitConfig(origin *das.V1GitRepoConfig, src *config.Source) *config.Secret {

	src.Git.Repo = origin.URL

	if origin.Commit != "" {
		src.Git.Commit = &origin.Commit
	} else if origin.Reference != "" {
		src.Git.Reference = &origin.Reference
	}

	if origin.Path != "" {
		src.Git.Path = &origin.Path
	}

	var secret *config.Secret

	if origin.Credentials != "" {
		secret = &config.Secret{}
		secret.Name = origin.Credentials
		src.Git.Credentials = &config.SecretRef{Name: secret.Name}
	} else if origin.SSHCredentials.PrivateKey != "" {
		secret = &config.Secret{}
		secret.Name = origin.SSHCredentials.PrivateKey
		src.Git.Credentials = &config.SecretRef{Name: secret.Name}
	}

	return secret
}

func migrateV1Selector(v1 *das.V1Stack, module *ast.Module) (config.Selector, error) {
	selector, ok, err := migrateV1SelectorLogic(module)
	if err != nil {
		return selector, err
	} else if !ok {
		if err := selector.Set(staticStackMatchLabelKey, []string{v1.Name}); err != nil {
			return config.Selector{}, fmt.Errorf("failed to set static stack match label for %q: %w", v1.Name, err)
		}
	}
	if err := selector.Set("system-type", []string{v1.Type}); err != nil {
		return selector, fmt.Errorf("failed to set system-type label for %q: %w", v1.Name, err)
	}
	return selector, nil
}

func migrateV1SelectorLogic(module *ast.Module) (config.Selector, bool, error) {
	var selector config.Selector
	var matchAllFound bool
	var excludeIsEmpty bool
	done := func() bool { return matchAllFound && selector.Len() > 0 && excludeIsEmpty }

	if len(module.Rules) != 1 {
		return config.Selector{}, false, nil
	}

	r := module.Rules[0]
	if !r.Head.Name.Equal(ast.Var("systems")) {
		return config.Selector{}, false, nil
	}

	var innerErr error
	ast.WalkExprs(r, func(x *ast.Expr) bool {
		if innerErr != nil {
			return true
		}
		if done() {
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
					} else if len(sl) == 0 {
						if err := selector.Set(k, []string{}); err != nil {
							innerErr = err
							return true
						}
					} else {
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
			} else if ops[0].Equal(ast.VarTerm("exclude")) {
				val, err := ast.JSON(ops[1].Value)
				if err != nil {
					innerErr = err
					return true
				}
				if obj, ok := val.(map[string]any); ok && len(obj) == 0 {
					excludeIsEmpty = true
				}
			}
		} else if terms, ok := x.Terms.([]*ast.Term); ok {
			// look for "match.all(_, include, exclude)"
			// ignore metadata
			exp := map[int]*ast.Term{
				0: ast.RefTerm(ast.VarTerm("match"), ast.StringTerm("all")),
				2: ast.VarTerm("include"),
				3: ast.VarTerm("exclude"),
			}
			for pos := range exp {
				if pos >= len(terms) || !terms[pos].Equal(exp[pos]) {
					return false
				}
			}
			matchAllFound = !x.Negated
		}

		return false
	})

	if innerErr != nil {
		return config.Selector{}, false, innerErr
	}

	if !done() {
		return config.Selector{}, false, nil
	}

	// NOTE(tsandall): DAS matching also takes into account the type information on the system/stack
	// since we don't have those in Lighthouse we need to exclude stacks that have an empty selector
	// because otherwise an empty selector matches ALL systems.
	//
	// NOTE(tsandall): users should just remove stacks from DAS with empty selectors.
	if selector.Len() == 0 {
		if err := selector.Set("do-not-match", []string{}); err != nil {
			return selector, false, err
		}
	}

	return selector, true, nil
}

func getSystemGitRoots(c *das.Client, sbomEnabled bool, v1 *das.V1System) ([]string, error) {

	if v1.SourceControl == nil {
		return nil, nil
	}

	if !sbomEnabled {
		return []string{""}, nil
	}

	log.Infof("Fetching git roots and labels for system %q", v1.Name)

	resp, err := c.JSON("v1/systems/" + v1.Id + "/bundles")
	if err != nil {
		return nil, err
	}

	bundles := []*das.V1Bundle{}
	if err := resp.Decode(&bundles); err != nil {
		return nil, err
	}

	var gitRoots []string
	if len(bundles) > 0 {
		for i := range bundles[0].SBOM.Origins {
			gitRoots = append(gitRoots, bundles[0].SBOM.Origins[i].Roots...)
		}
	}

	return gitRoots, nil
}

func getStackGitRoots(c *das.Client, sbomEnabled bool, v1 *das.V1Stack) ([]string, error) {

	if v1.SourceControl == nil {
		return nil, nil
	}

	if len(v1.MatchingSystems) == 0 || !sbomEnabled {
		return []string{""}, nil
	}

	log.Infof("Fetching git roots for stack %q", v1.Name)

	resp, err := c.JSON("v1/systems/" + v1.MatchingSystems[0] + "/bundles")
	if err != nil {
		return nil, err
	}

	bundles := []*das.V1Bundle{}
	if err := resp.Decode(&bundles); err != nil {
		return nil, err
	}

	var gitRoots []string
	if len(bundles) > 0 {
		for i := range bundles[0].SBOM.Origins {
			for _, root := range bundles[0].SBOM.Origins[i].Roots {
				if strings.HasPrefix(root, "stacks/"+v1.Id+"/") {
					gitRoots = append(gitRoots, root)
				}
			}
		}
	}

	return gitRoots, nil
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

		src := output.Sources[state.SystemsById[id].Name]
		src.Requirements = append(src.Requirements, rs...)
	}

	for id, policies := range state.StackPolicies {
		rs, err := getRequirementsForPolicies(policies, index, "")
		if err != nil {
			return err
		}
		src := output.Sources[state.StacksById[id].Name]
		src.Requirements = append(src.Requirements, rs...)
	}

	for id, policies := range state.LibraryPolicies {
		rs, err := getRequirementsForPolicies(policies, index, id)
		if err != nil {
			return err
		}
		src := output.Sources[id]
		src.Requirements = append(src.Requirements, rs...)
	}

	return nil
}

func getRequirementsForPolicies(policies []*das.V1Policy, index *libraryPackageIndex, ignore string) ([]config.Requirement, error) {
	librarySet := map[string]struct{}{}
	for _, p := range policies {
		for file, content := range p.Modules {
			if filepath.Ext(file) != ".rego" {
				continue
			}
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
		rs = append(rs, config.Requirement{Source: &id})
	}
	sort.Slice(rs, func(i, j int) bool {
		return *rs[i].Source < *rs[j].Source
	})
	return rs, nil
}

func pruneConfig(root *config.Root) ([]*config.Stack, []*config.Source, []*config.Secret) {

	var removedStacks []*config.Stack
	var removedSources []*config.Source
	var removedSecrets []*config.Secret

	for _, stack := range root.Stacks {
		var found bool
		for _, b := range root.Bundles {
			if stack.Selector.Matches(b.Labels) {
				found = true
			}
		}
		if !found {
			delete(root.Stacks, stack.Name)
			removedStacks = append(removedStacks, stack)
		}
	}

	g := make(graph)

	for _, b := range root.Bundles {
		for _, r := range b.Requirements {
			if r.Source != nil {
				g[*r.Source] = append(g[*r.Source], node{name: b.Name})
			}
		}
	}

	for _, stack := range root.Stacks {
		for _, r := range stack.Requirements {
			if r.Source != nil {
				g[*r.Source] = append(g[*r.Source], node{name: stack.Name})
			}
		}
	}

	for _, src := range root.Sources {
		for _, r := range src.Requirements {
			if r.Source != nil {
				g[*r.Source] = append(g[*r.Source], node{name: src.Name, lib: true})
			}
		}
	}

	for _, src := range root.Sources {
		var found bool
		g.DFS(src.Name, func(n node) {
			if !n.lib {
				found = true
			}
		})
		if !found {
			delete(root.Sources, src.Name)
			removedSources = append(removedSources, src)
		}
	}

	credentials := make(map[string]struct{})
	for _, lib := range root.Sources {
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

	return removedStacks, removedSources, removedSecrets
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
	FeatureFlags struct {
		SBOM                  bool `json:"SBOM"`
		LibraryEditingEnabled bool `json:"LIBRARY_EDITING_ENABLED"`
	}
	SpecificSystemsIds map[string]struct{}
	DatasourcesById    map[string]*das.V1Datasource
	SystemsById        map[string]*das.V1System
	SystemPolicies     map[string][]*das.V1Policy
	StacksById         map[string]*das.V1Stack
	StackPolicies      map[string][]*das.V1Policy
	LibrariesById      map[string]*das.V1Library
	LibraryPolicies    map[string][]*das.V1Policy
}

type dasFetchOptions struct {
	SystemId string
}

func fetchDASState(c *das.Client, opts dasFetchOptions) (*dasState, error) {
	state := dasState{}

	log.Info("Fetching v1/runtime/features")
	resp, err := c.JSON("v1/runtime/features")
	if err != nil {
		return nil, err
	}

	if err := resp.Decode(&state.FeatureFlags); err != nil {
		return nil, err
	}

	var systems []*das.V1System

	if opts.SystemId == "" {
		log.Info("Fetching v1/systems")
		resp, err := c.JSON("v1/systems", das.Params{Query: map[string]string{
			"authz":       "false",
			"compact":     "true",
			"datasources": "true",
			"errors":      "false",
			"metadata":    "false",
			"modules":     "false",
			"policies":    "true",
			"rule_counts": "false",
		}})
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

	var libraries []*das.V1Library

	if state.FeatureFlags.LibraryEditingEnabled {

		log.Info("Fetching v1/libraries")
		resp, err = c.JSON("v1/libraries")
		if err != nil {
			return nil, err
		}

		err = resp.Decode(&libraries)
		if err != nil {
			return nil, err
		}
	} else {

		log.Info("Fetching v1/datasources")
		resp, err = c.JSON("v1/datasources")
		if err != nil {
			return nil, err
		}

		var datasources []*das.V1Datasource
		if err := resp.Decode(&datasources); err != nil {
			return nil, err
		}

		for i := range datasources {
			if datasources[i].Type == "pull" && datasources[i].Category == "git/rego" && strings.HasPrefix(datasources[i].Id, "global/") {
				resp, err := c.JSON("v1/datasources/" + datasources[i].Id)
				if err != nil {
					return nil, err
				}
				var git das.V1GitRepoConfig
				if err := resp.Decode(&git); err != nil {
					return nil, err
				}
				library, err := fetchLegacyLibrary(c, datasources[i].Id, git)
				if err != nil {
					return nil, err
				}
				libraries = append(libraries, library)
			}
		}
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

func fetchLegacyLibrary(c *das.Client, id string, git das.V1GitRepoConfig) (*das.V1Library, error) {

	log.Infof("Fetching legacy library %q", id)

	var library das.V1Library

	library.Id = id
	library.SourceControl = &das.V1LibrarySourceControl{Origin: git, LibraryOrigin: git}

	process := []string{id}
	seen := map[string]struct{}{}

	for len(process) > 0 {
		var next string
		next, process = process[0], process[1:]
		seen[next] = struct{}{}
		resp, err := c.JSON("v1/policies/" + next)
		if err != nil {
			return nil, err
		}
		var x struct {
			Modules  map[string]string `json:"modules"`
			Packages []string          `json:"packages"`
		}
		if err := resp.Decode(&x); err != nil {
			return nil, err
		}
		if len(x.Modules) > 0 {
			library.Policies = append(library.Policies, das.V1PoliciesRef{Id: next})
		}
		for _, pkg := range x.Packages {
			id := next + "/" + pkg
			if _, ok := seen[id]; !ok {
				process = append(process, id)
			}
		}
	}

	return &library, nil
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

				// Legacy libraries will have had policies fetched, but
				// v1/libraries do not include policies in the list endpoint.
				if len(l.Policies) == 0 {
					// List libraries differs from systems/stacks. Result does not
					// have policies on it. Need to fetch each library individually.
					resp, err := c.JSON("v1/libraries/"+l.Id, das.Params{
						Query: map[string]string{
							"rule_counts":       "false",
							"modules":           "false",
							"dependant_bundles": "none",
						},
					})
					if err != nil {
						panic(err)
					}

					if err := resp.Decode(l); err != nil {
						panic(err)
					}
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
		if len(rParts) == 1 && rParts[0] == "" {
			return true // empty root matches everything
		}
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
