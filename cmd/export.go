package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/open-policy-agent/opa/bundle"
	"github.com/spf13/cobra"
	"github.com/tsandall/lighthouse/internal/config"
)

type exportParams struct {
	url   string
	token string
}

func init() {

	var params exportParams

	params.token = os.Getenv("STYRA_TOKEN")

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export configuration from Styra",
		Run: func(cmd *cobra.Command, args []string) {
			if err := doExport(params); err != nil {
				log.Fatal(err)
			}
		},
	}

	cmd.Flags().StringVarP(&params.url, "url", "u", "", "Styra tenant URL (e.g., https://expo.styra.com)")

	RootCommand.AddCommand(
		cmd,
	)
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

func mapV1SystemToSystemAndSecretConfig(client *DASClient, v1 *v1System) (*config.System, *config.Secret, error) {
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

func getNonGitFilesForSystem(client *DASClient, id string) (config.Files, error) {

	log.Printf("Fetching bundle for system %q...", id)

	resp, err := client.JSON("v1/systems/" + id + "/bundles")
	if err != nil {
		return nil, err
	}

	bundles := []*v1Bundle{}
	if err := resp.Decode(&bundles); err != nil {
		return nil, err
	}

	result := config.Files{}

	if len(bundles) > 0 {
		var roots []string
		for i := range bundles[0].SBOM.Origins {
			roots = append(roots, bundles[0].SBOM.Origins[i].Roots...)
		}

		resp, err := client.Get(strings.TrimPrefix(bundles[0].DownloadURL, client.url))
		if err != nil {
			return nil, err
		}

		b, err := bundle.NewReader(resp.Body).WithLazyLoadingMode(true).Read()
		if err != nil {
			return nil, err
		}

		for _, mf := range b.Modules {
			if !rootsPrefix(roots, mf.Path) {
				result[mf.Path] = string(mf.Raw)
			}
		}

		for _, rf := range b.Raw {
			if filepath.Base(rf.Path) == "data.json" && !rootsPrefix(roots, rf.Path) {
				result[rf.Path] = string(rf.Value)
			}
		}
	}

	return result, nil
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

func doExport(params exportParams) error {

	if params.url == "" {
		return fmt.Errorf("Please set Styra DAS URL with -u flag (e.g., https://example.styra.com)")
	}

	if params.token == "" {
		return fmt.Errorf("Please set STYRA_TOKEN environment variable to token with WorkspaceViewer permission.")
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

	for _, system := range systems {
		sc, secret, err := mapV1SystemToSystemAndSecretConfig(&c, system)
		if err != nil {
			return err
		}

		sc.Files, err = getNonGitFilesForSystem(&c, system.Id)
		if err != nil {
			return err
		}

		output.Systems[sc.Name] = sc

		if secret != nil {
			output.Secrets[secret.Name] = secret
		}
	}

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

	log.Printf("Finished downloading resources from DAS. Dumping configuration.\n\n")

	bs, err := yaml.Marshal(output)
	if err != nil {
		return err
	}

	fmt.Println(string(bs))
	return nil
}

type v1System struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Policies []struct {
		Id string `json:"id"`
	} `json:"policies"`
	SourceControl *struct {
		Origin v1GitRepoConfig `json:"origin"`
	} `json:"source_control"`
	MatchingStacks []string `json:"matching_stacks"`
}

type v1Secret struct {
	Name string `json:"name"`
	Id   string `json:"id"`
}

type v1Library struct {
	Id            string `json:"id"`
	SourceControl *struct {
		UseWorkspaceSettings bool            `json:"use_workspace_settings"`
		LibraryOrigin        v1GitRepoConfig `json:"library_origin"`
	} `json:"source_control"`
}

type v1Stack struct {
	Name     string `json:"name"`
	Id       string `json:"id"`
	Type     string `json:"type"`
	Policies []struct {
		Id string `json:"id"`
	} `json:"policies"`
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

type v1Policy struct {
	Modules map[string]string `json:"modules"`
}
