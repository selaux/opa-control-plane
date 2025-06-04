package das

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"
)

type V1System struct {
	Id            string          `json:"id"`
	Name          string          `json:"name"`
	Type          string          `json:"type"`
	Policies      []V1PoliciesRef `json:"policies"`
	SourceControl *struct {
		Origin V1GitRepoConfig `json:"origin"`
	} `json:"source_control"`
	MatchingStacks []string `json:"matching_stacks"`
	Datasources    []struct {
		Id string `json:"id"`
	}
}

type V1Library struct {
	Id            string                  `json:"id"`
	Policies      []V1PoliciesRef         `json:"policies"`
	SourceControl *V1LibrarySourceControl `json:"source_control"`
}

type V1LibrarySourceControl struct {
	UseWorkspaceSettings bool            `json:"use_workspace_settings"`
	Origin               V1GitRepoConfig `json:"origin"`
	LibraryOrigin        V1GitRepoConfig `json:"library_origin"`
}

type V1Stack struct {
	Name          string          `json:"name"`
	Id            string          `json:"id"`
	Type          string          `json:"type"`
	Policies      []V1PoliciesRef `json:"policies"`
	SourceControl *struct {
		UseWorkspaceSettings bool            `json:"use_workspace_settings"`
		Origin               V1GitRepoConfig `json:"origin"`
		StackOrigin          V1GitRepoConfig `json:"stack_origin"`
	} `json:"source_control"`
	MatchingSystems []string `json:"matching_systems"`
}

type V1Datasource struct {
	Id       string `json:"id"`
	Category string `json:"category"`
	Type     string `json:"type"`
}

type V1GitRepoConfig struct {
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

type V1Bundle struct {
	DownloadURL string `json:"download_url"`
	SBOM        struct {
		Origins []struct {
			Roots []string `json:"roots"`
		} `json:"origins"`
	} `json:"sbom"`
}

type V1Decisions struct {
	Items []V1Decision `json:"items"`
}

type V1Decision struct {
	DecisionId string `json:"decision_id"`
	Bundles    map[string]struct {
		Revision string `json:"revision"`
	} `json:"bundles"`
	Path    string       `json:"path"`
	Input   *interface{} `json:"input"`
	Result  *interface{} `json:"result"`
	Metrics struct {
		TimerRegoQueryCompileNs int64 `json:"timer_rego_query_compile_ns"`
		TimerRegoQueryEvalNs    int64 `json:"timer_rego_query_eval_ns"`
		TimerReqoQueryParseNs   int64 `json:"timer_rego_query_parse_ns"`
	} `json:"metrics"`
}

type V1PoliciesRef struct {
	Id string `json:"id"`
}

type V1Policy struct {
	Package string            `json:"package"`
	Modules map[string]string `json:"modules"`
}

type Client struct {
	URL    string
	Token  string
	Client *http.Client
}

type Response struct {
	Result    json.RawMessage `json:"result"`
	RequestId string          `json:"request_id"`
}

func (r *Response) Decode(x interface{}) error {
	buf := bytes.NewBuffer(r.Result)
	decoder := json.NewDecoder(buf)
	return decoder.Decode(x)
}

type Params struct {
	Query map[string]string
}

func (c *Client) Get(path string, params ...Params) (*http.Response, error) {
	url := fmt.Sprintf("%v/%v", c.URL, "/"+strings.TrimPrefix(path, "/"))

	var p Params
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

	req.Header.Add("authorization", fmt.Sprintf("Bearer %v", c.Token))

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, Error{URL: url, Method: "GET", StatusCode: resp.StatusCode}
	}

	return resp, nil

}

type Error struct {
	URL        string
	Method     string
	StatusCode int
}

func (e Error) Error() string {
	return fmt.Sprintf("DAS returned unexpected status code (%v) for %v %v", e.StatusCode, e.Method, e.URL)
}

func (c *Client) JSON(path string, params ...Params) (*Response, error) {

	resp, err := c.Get(path, params...)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var r Response
	return &r, decoder.Decode(&r)
}
