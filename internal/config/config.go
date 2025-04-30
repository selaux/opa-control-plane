package config

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Internal configuration data structures for Lighthouse.

// Root is the top-level configuration structure used by Lighthouse.
type Root struct {
	Systems map[string]*System `yaml:"systems"`
	Secrets map[string]*Secret `yaml:"secrets"`
}

// UnmarshalYAML implements the yaml.Marshaler interface for the Root struct. This
// lets us define Lighthouse resources in a more user-friendly way with mappings
// where keys are the resource names. It is also used to inject the secret store
// into each secret reference so that internal callers can resolve secret values
// as needed.
func (r *Root) UnmarshalYAML(node *yaml.Node) error {
	type rawRoot Root // avoid recursive calls to UnmarshalYAML by type aliasing
	var raw rawRoot

	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("failed to decode Root: %w", err)
	}

	for name, secret := range raw.Secrets {
		secret.Name = name
	}

	for name, system := range raw.Systems {
		system.Name = name
		if system.Git.Credentials != nil {
			system.Git.Credentials.value = raw.Secrets[system.Git.Credentials.Name]
		}
		if system.ObjectStorage.AmazonS3 != nil && system.ObjectStorage.AmazonS3.Credentials != nil {
			system.ObjectStorage.AmazonS3.Credentials.value = raw.Secrets[system.ObjectStorage.AmazonS3.Credentials.Name]
		}
		// TODO: Handle other object storage types (GCP, Azure) similarly
	}

	*r = Root(raw) // Assign the unmarshaled data back to the original struct
	return nil
}

// System defines the configuration for a Lighthouse System.
type System struct {
	Name          string        `yaml:"-"`
	Git           Git           `yaml:"git"`
	ObjectStorage ObjectStorage `yaml:"object_storage"`
}

func (s *System) Equal(other *System) bool {
	if s == other {
		return true
	}

	if s == nil || other == nil {
		return false
	}

	return s.Name == other.Name && s.Git.Equal(&other.Git) && s.ObjectStorage.Equal(&other.ObjectStorage)
}

// Git defines the Git synchronization configuration used by Lighthouse
// resources like Systems, Stacks, and Libraries.
type Git struct {
	Repo        string     `yaml:"repo"`
	Reference   *string    `yaml:"reference,omitempty"`
	Commit      *string    `yaml:"commit,omitempty"`
	Path        *string    `yaml:"path,omitempty"`
	Credentials *SecretRef `yaml:"credentials,omitempty"`
}

func (g *Git) Equal(other *Git) bool {
	if g == other {
		return true
	}

	if g == nil || other == nil {
		return false
	}

	return stringEqual(g.Reference, other.Reference) && stringEqual(g.Commit, other.Commit) && stringEqual(g.Path, other.Path) && g.Credentials.Equal(other.Credentials)
}

type SecretRef struct {
	Name  string `yaml:"name,omitempty"`
	value *Secret
}

func (s *SecretRef) Resolve() (*Secret, error) {
	if s.value == nil {
		return nil, fmt.Errorf("secret %q not found", s.Name)
	}
	return s.value, nil
}

func (s *SecretRef) MarshalYAML() (interface{}, error) {
	if s.Name == "" {
		return nil, nil
	}
	return s.Name, nil
}

func (s *SecretRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return n.Decode(&s.Name)
	}
	return fmt.Errorf("expected scalar node, got %v", n.Kind)
}

func (s *SecretRef) Equal(other *SecretRef) bool {
	if s == other {
		return true
	}

	if s == nil || other == nil {
		return false
	}

	return s.Name == other.Name // No need to compare values, as they are resolved at runtime
}

// Secret defines the configuration for secrets/tokens used by Lighthouse
// for Git synchronization, datasources, etc.
type Secret struct {
	Name  string                 `yaml:"-"`
	Value map[string]interface{} `yaml:"value,omitempty"`
}

func (s *Secret) Ref() *SecretRef {
	return &SecretRef{Name: s.Name, value: s}
}

func (s *Secret) MarshalYAML() (interface{}, error) {
	if len(s.Value) == 0 {
		return map[string]interface{}{}, nil
	}
	return s.Value, nil
}

func (s *Secret) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.MappingNode {
		return n.Decode(&s.Value)
	}
	return fmt.Errorf("expected mapping node, got %v", n.Kind)
}

func ParseFile(filename string) (root *Root, err error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", filename, err)
	}

	return Parse(bytes.NewReader(bs))
}

func Parse(r io.Reader) (root *Root, err error) {
	bs, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(bs, &root); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return root, nil
}

type ObjectStorage struct {
	AmazonS3         *AmazonS3         `yaml:"aws,omitempty"`
	GCPCloudStorage  *GCPCloudStorage  `yaml:"gcp,omitempty"`
	AzureBlobStorage *AzureBlobStorage `yaml:"azure,omitempty"`
}

func (o *ObjectStorage) Equal(other *ObjectStorage) bool {
	if o == other {
		return true
	}

	if o == nil || other == nil {
		return false
	}

	return o.AmazonS3.Equal(other.AmazonS3) && o.GCPCloudStorage.Equal(other.GCPCloudStorage) && o.AzureBlobStorage.Equal(other.AzureBlobStorage)
}

// AmazonS3 defines the configuration for an Amazon S3-compatible object storage.
type AmazonS3 struct {
	Bucket      string     `yaml:"bucket"`
	Key         string     `yaml:"key"`
	Region      string     `yaml:"region,omitempty"`
	Credentials *SecretRef `yaml:"credentials,omitempty"`
}

// GCPCloudStorage defines the configuration for a Google Cloud Storage bucket.
type GCPCloudStorage struct {
	Project string `yaml:"project"`
	Bucket  string `yaml:"bucket"`
	Object  string `yaml:"object"`
}

// AzureBlobStorage defines the configuration for an Azure Blob Storage container.
type AzureBlobStorage struct {
	AccountURL string `yaml:"account_url"`
	Container  string `yaml:"container"`
	Path       string `yaml:"path"`
}

func (a *AmazonS3) Equal(other *AmazonS3) bool {
	if a == other {
		return true
	}

	if a == nil || other == nil {
		return false
	}

	return a.Bucket == other.Bucket && a.Key == other.Key && a.Region == other.Region && a.Credentials.Equal(other.Credentials)
}

func (g *GCPCloudStorage) Equal(other *GCPCloudStorage) bool {
	if g == other {
		return true
	}

	if g == nil || other == nil {
		return false
	}

	return g.Project == other.Project && g.Bucket == other.Bucket && g.Object == other.Object
}

func (a *AzureBlobStorage) Equal(other *AzureBlobStorage) bool {
	if a == other {
		return true
	}

	if a == nil || other == nil {
		return false
	}

	return a.AccountURL == other.AccountURL && a.Container == other.Container && a.Path == other.Path
}

func stringEqual(a, b *string) bool {
	if a == b {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	return *a == *b
}
