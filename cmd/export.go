package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

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

func (c *DASClient) Get(path string) (*DASResponse, error) {
	url := fmt.Sprintf("%v/%v", c.url, "/"+strings.TrimPrefix(path, "/"))
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
		return nil, fmt.Errorf("DAS returned unexpected status code (%v) for %v %v", resp.StatusCode, "GET", url)
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var r DASResponse
	return &r, decoder.Decode(&r)
}

func mapV1SystemToSystemAndSecretConfig(v1 *v1System, secretsById map[string]*v1Secret) (*config.System, *config.Secret, error) {
	var system config.System
	var secret config.Secret

	system.Name = v1.Name

	if v1.SourceControl == nil {
		return nil, nil, fmt.Errorf("not git backed")
	}

	system.Git.Repo = v1.SourceControl.Origin.URL

	if v1.SourceControl.Origin.Commit != "" {
		system.Git.Commit = &v1.SourceControl.Origin.Commit
	} else if v1.SourceControl.Origin.Reference != "" {
		system.Git.Reference = &v1.SourceControl.Origin.Reference
	} else {
		return nil, nil, fmt.Errorf("origin missing commit and reference")
	}

	if v1.SourceControl.Origin.Path != "" {
		system.Git.Path = &v1.SourceControl.Origin.Path
	}

	if v1.SourceControl.Origin.Credentials != "" {
		secret.Name = v1.SourceControl.Origin.Credentials
		if s, ok := secretsById[v1.SourceControl.Origin.Credentials]; ok {
			secret.Value = map[string]interface{}{
				"type":     "http_basic_auth",
				"username": s.Name,
			}
		}
		system.Git.Credentials = &config.SecretRef{Name: secret.Name}
	} else {
		return nil, nil, fmt.Errorf("non-http auth credentials not supported yet")
	}

	return &system, &secret, nil
}

func mapV1LibraryToLibraryAndSecretConfig(v1 *v1Library, secretsById map[string]*v1Secret) (*config.Library, *config.Secret, error) {

	if v1.SourceControl.UseWorkspaceSettings {
		return nil, nil, fmt.Errorf("workspace source control not supported yet")
	}

	var library config.Library
	var secret config.Secret

	library.Name = v1.Id

	if v1.SourceControl.LibraryOrigin.URL == "" {
		return nil, nil, fmt.Errorf("not git backed")
	}

	library.Git.Repo = v1.SourceControl.LibraryOrigin.URL

	if v1.SourceControl.LibraryOrigin.Commit != "" {
		library.Git.Commit = &v1.SourceControl.LibraryOrigin.Commit
	} else if v1.SourceControl.LibraryOrigin.Reference != "" {
		library.Git.Reference = &v1.SourceControl.LibraryOrigin.Reference
	} else {
		return nil, nil, fmt.Errorf("missing commit and reference")
	}

	if v1.SourceControl.LibraryOrigin.Path != "" {
		library.Git.Path = &v1.SourceControl.LibraryOrigin.Path
	}

	if v1.SourceControl.LibraryOrigin.Credentials != "" {
		secret.Name = v1.SourceControl.LibraryOrigin.Credentials
		if s, ok := secretsById[v1.SourceControl.LibraryOrigin.Credentials]; ok {
			secret.Value = map[string]interface{}{
				"type":     "http_basic_auth",
				"username": s.Name,
			}
		}
		library.Git.Credentials = &config.SecretRef{Name: secret.Name}
	}

	return &library, &secret, nil
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

	log.Println("Fetching v1/systems...")
	resp, err := c.Get("v1/systems")
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
	resp, err = c.Get("v1/libraries")
	if err != nil {
		return err
	}

	var libraries []*v1Library
	err = resp.Decode(&libraries)
	if err != nil {
		return err
	}

	log.Printf("Received %d libraries.", len(libraries))

	log.Println("Fetching v1/secrets...")
	resp, err = c.Get("v1/secrets")
	if err != nil {
		return err
	}

	var secrets []*v1Secret
	err = resp.Decode(&secrets)
	if err != nil {
		return err
	}

	log.Printf("Received %d secrets.", len(secrets))

	secretsById := map[string]*v1Secret{}
	for _, secret := range secrets {
		secretsById[secret.Id] = secret
	}

	for _, system := range systems {
		sc, secret, err := mapV1SystemToSystemAndSecretConfig(system, secretsById)
		if err != nil {
			log.Printf("Skipping system %q: %v.", system.Name, err)
			continue
		}

		output.Systems[sc.Name] = sc
		output.Secrets[secret.Name] = secret
	}

	for _, library := range libraries {
		lc, secret, err := mapV1LibraryToLibraryAndSecretConfig(library, secretsById)
		if err != nil {
			log.Printf("Skipping library %q: %v.", library.Id, err)
			continue
		}

		output.Libraries[lc.Name] = lc
		output.Secrets[secret.Name] = secret
	}

	log.Printf("Finished downloading resources from DAS. Dumping configuration.\n\n")
	fmt.Printf("# Generated from %v at %v.\n", params.url, time.Now().UTC().Format(time.RFC3339))

	bs, err := yaml.Marshal(output)
	if err != nil {
		return err
	}

	fmt.Println(string(bs))
	return nil
}

type v1System struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	SourceControl *struct {
		Origin v1GitRepoConfig `json:"origin"`
	} `json:"source_control"`
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
	Name          string `json:"name"`
	Id            string `json:"id"`
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
