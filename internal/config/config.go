package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/gobwas/glob"
	"gopkg.in/yaml.v3"
)

// Internal configuration data structures for Lighthouse.

// Metadata contains metadata about the configuration file itself. This
// information is not stored in the database and is only used by the migration
// tooling.
type Metadata struct {
	ExportedFrom string `yaml:"exported_from"`
	ExportedAt   string `yaml:"exported_at"`
}

// Root is the top-level configuration structure used by Lighthouse.
type Root struct {
	Metadata  Metadata            `yaml:"metadata,omitempty"`
	Systems   map[string]*System  `yaml:"systems,omitempty"`
	Stacks    map[string]*Stack   `yaml:"stacks,omitempty"`
	Libraries map[string]*Library `yaml:"libraries,omitempty"`
	Secrets   map[string]*Secret  `yaml:"secrets,omitempty"`
	Database  Database            `yaml:"database,omitempty"`
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
		if system.ObjectStorage.AzureBlobStorage != nil && system.ObjectStorage.AzureBlobStorage.Credentials != nil {
			system.ObjectStorage.AzureBlobStorage.Credentials.value = raw.Secrets[system.ObjectStorage.AzureBlobStorage.Credentials.Name]
		}
		if system.ObjectStorage.GCPCloudStorage != nil && system.ObjectStorage.GCPCloudStorage.Credentials != nil {
			system.ObjectStorage.GCPCloudStorage.Credentials.value = raw.Secrets[system.ObjectStorage.GCPCloudStorage.Credentials.Name]
		}
	}

	for name, library := range raw.Libraries {
		library.Name = name
		if library.Git.Credentials != nil {
			library.Git.Credentials.value = raw.Secrets[library.Git.Credentials.Name]
		}
	}

	for name, stack := range raw.Stacks {
		stack.Name = name
	}

	*r = Root(raw) // Assign the unmarshaled data back to the original struct
	return nil
}

// System defines the configuration for a Lighthouse System.
type System struct {
	Name          string        `yaml:"-"`
	Labels        Labels        `yaml:"labels,omitempty"`
	Git           Git           `yaml:"git,omitempty"`
	ObjectStorage ObjectStorage `yaml:"object_storage,omitempty"`
	Datasources   []Datasource  `yaml:"datasources,omitempty"`
	Files         Files         `yaml:"files,omitempty"`
	Requirements  []Requirement `yaml:"requirements,omitempty"`
}

type Labels map[string]string

type Requirement struct {
	Library *string `yaml:"library,omitempty"`
}

func (a Requirement) Equal(b Requirement) bool {
	return stringEqual(a.Library, b.Library)
}

type Files map[string]string

func (f Files) Equal(other Files) bool {
	if len(f) != len(other) {
		return false
	}
	for k := range other {
		if other[k] != f[k] {
			return false
		}
	}
	return true
}

func (f Files) MarshalYAML() (interface{}, error) {
	encodedMap := make(map[string]string)
	for key, value := range f {
		encodedValue := base64.StdEncoding.EncodeToString([]byte(value))
		encodedMap[key] = encodedValue
	}
	return encodedMap, nil
}

func (f *Files) UnmarshalYAML(node *yaml.Node) error {
	raw := map[string]string{}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*f = Files{}
	for key, encodedValue := range raw {
		decodedBytes, err := base64.StdEncoding.DecodeString(encodedValue)
		if err != nil {
			return fmt.Errorf("failed to decode value for key %q: %w", key, err)
		}
		(*f)[key] = string(decodedBytes)
	}
	return nil
}

func (s *System) Equal(other *System) bool {
	if s == other {
		return true
	}

	if s == nil || other == nil {
		return false
	}

	return s.Name == other.Name && s.Git.Equal(&other.Git) && s.ObjectStorage.Equal(&other.ObjectStorage) && equalDatasources(s.Datasources, other.Datasources) && s.Files.Equal(other.Files) && equalRequirements(s.Requirements, other.Requirements)
}

func equalRequirements(a, b []Requirement) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !a[k].Equal(b[k]) {
			return false
		}
	}
	return true
}

// Library defines the configuration for a Lighthouse Library.
type Library struct {
	Name         string        `yaml:"-"`
	Git          Git           `yaml:"git,omitempty"`
	Datasources  []Datasource  `yaml:"datasources,omitempty"`
	Files        Files         `yaml:"files,omitempty"`
	Requirements []Requirement `yaml:"requirements,omitempty"`
}

func (s *Library) Equal(other *Library) bool {
	if s == other {
		return true
	}

	if s == nil || other == nil {
		return false
	}

	return s.Name == other.Name && s.Git.Equal(&other.Git) && equalDatasources(s.Datasources, other.Datasources) && s.Files.Equal(other.Files) && equalRequirements(s.Requirements, other.Requirements)
}

// Stack defines the configuration for a Lighthouse Stack.
type Stack struct {
	Name         string        `yaml:"-"`
	Selector     Selector      `yaml:"selector"`
	Requirements []Requirement `yaml:"requirements,omitempty"`
}

func (a *Stack) Equal(other *Stack) bool {
	if a == other {
		return true
	}
	if a == nil || other == nil {
		return false
	}
	return a.Name == other.Name && a.Selector.Equal(other.Selector) && equalRequirements(a.Requirements, other.Requirements)
}

type Selector struct {
	s map[string][]string
	m map[string][]glob.Glob // Pre-compiled glob patterns for faster matching
}

// Matches checks if the given labels match the selector.
func (s *Selector) Matches(labels Labels) bool {
	for expLabel, expValues := range s.m {
		v, ok := labels[expLabel]
		if !ok {
			return false
		}
		found := len(expValues) == 0 // empty selector value matches any label value
		for _, ev := range expValues {
			if ev.Match(v) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (s Selector) Equal(other Selector) bool {
	if len(s.s) != len(other.s) {
		return false
	}
	for k := range s.s {
		if !equalStringSets(s.s[k], other.s[k]) {
			return false
		}
	}
	return true
}

func (s *Selector) UnmarshalYAML(node *yaml.Node) error {
	raw := make(map[string][]string)
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*s = Selector{s: make(map[string][]string), m: make(map[string][]glob.Glob)}
	for key, encodedValue := range raw {
		s.Set(key, encodedValue)
	}
	return nil
}

func (s Selector) MarshalYAML() (interface{}, error) {
	encodedMap := make(map[string][]string)
	for key, value := range s.s {
		encodedMap[key] = value
	}
	return encodedMap, nil
}

func (s *Selector) Get(key string) ([]string, bool) {
	if s.s == nil {
		return nil, false
	}

	v, ok := s.s[key]
	return v, ok
}

func (s *Selector) Set(key string, value []string) error {
	if s.s == nil {
		s.s = make(map[string][]string)
		s.m = make(map[string][]glob.Glob)
	}

	if len(value) > 0 {
		for _, v := range value {
			g, err := glob.Compile(v)
			if err != nil {
				return fmt.Errorf("failed to decode value for key %q: %w", key, err)
			}
			s.m[key] = append(s.m[key], g)
		}
	} else {
		s.m[key] = []glob.Glob{}
	}

	s.s[key] = value
	return nil
}

func (s *Selector) Len() int {
	return len(s.s)
}

func equalStringSets(a, b []string) bool {
	sa := make(map[string]struct{})
	for i := range a {
		sa[a[i]] = struct{}{}
	}
	sb := make(map[string]struct{})
	for i := range b {
		sb[b[i]] = struct{}{}
	}
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if _, ok := sb[k]; !ok {
			return false
		}
	}
	return true
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

	if s.Name != other.Name {
		return false
	}

	return s.value.Equal(other.value)
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

func (s *Secret) Equal(other *Secret) bool {
	if s == other {
		return true
	}

	if s == nil || other == nil {
		return false
	}

	return s.Name == other.Name && reflect.DeepEqual(s.Value, other.Value)
}

// Get retrieves the values from any external source as necessary.
func (s *Secret) Get(ctx context.Context) (map[string]interface{}, error) {
	value := make(map[string]interface{}, len(s.Value))

	for k, v := range s.Value {
		if str, ok := v.(string); ok && str != "" {
			str = os.ExpandEnv(str)
			value[k] = str
		} else {
			value[k] = v // Keep non-string values as is
		}
	}

	return value, nil
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
	URL         string     `yaml:"url,omitempty"` // for test purposes
}

// GCPCloudStorage defines the configuration for a Google Cloud Storage bucket.
type GCPCloudStorage struct {
	Project     string     `yaml:"project"`
	Bucket      string     `yaml:"bucket"`
	Object      string     `yaml:"object"`
	Credentials *SecretRef `yaml:"credentials,omitempty"`
}

// AzureBlobStorage defines the configuration for an Azure Blob Storage container.
type AzureBlobStorage struct {
	AccountURL  string     `yaml:"account_url"`
	Container   string     `yaml:"container"`
	Path        string     `yaml:"path"`
	Credentials *SecretRef `yaml:"credentials,omitempty"`
}

func (a *AmazonS3) Equal(other *AmazonS3) bool {
	if a == other {
		return true
	}

	if a == nil || other == nil {
		return false
	}

	return a.Bucket == other.Bucket && a.Key == other.Key && a.Region == other.Region && a.Credentials.Equal(other.Credentials) && a.URL == other.URL
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

type Datasource struct {
	Name        string                 `yaml:"name"`
	Path        string                 `yaml:"path"`
	Type        string                 `yaml:"type"`
	Config      map[string]interface{} `yaml:"config,omitempty"`
	Credentials *SecretRef             `yaml:"credentials,omitempty"`
}

func (d *Datasource) Equal(other *Datasource) bool {
	if d == other {
		return true
	}

	if d == nil || other == nil {
		return false
	}

	if d.Name != other.Name || d.Path != other.Path || d.Type != other.Type {
		return false
	}

	if len(d.Config) != len(other.Config) {
		return false
	}

	for k, v := range d.Config {
		if ov, ok := other.Config[k]; !ok || !reflect.DeepEqual(v, ov) {
			return false
		}
	}

	return d.Credentials.Equal(other.Credentials)
}

type Database struct {
	SQL    *SQLDatabase `yaml:"sql,omitempty"`
	AWSRDS *AmazonRDS   `yaml:"aws_rds,omitempty"`
}

type SQLDatabase struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type AmazonRDS struct {
	Region       string     `yaml:"region"`
	Endpoint     string     `yaml:"endpoint"` // hostname:port
	Driver       string     `yaml:"driver"`   // mysql or postgres
	DatabaseUser string     `yaml:"database_user"`
	DatabaseName string     `yaml:"database_name"`
	Credentials  *SecretRef `yaml:"credentials,omitempty"`
}

func EqualLibraries(a, b []*Library) bool {
	m := make(map[string]*Library, len(a))
	for _, lib := range a {
		m[lib.Name] = lib
	}

	n := make(map[string]*Library, len(b))
	for _, lib := range b {
		n[lib.Name] = lib
	}

	if len(m) != len(n) {
		return false
	}

	for id, a := range m {
		b, ok := n[id]
		if !ok {
			return false
		}
		if !a.Equal(b) {
			return false
		}
	}

	return true
}

func EqualStacks(a, b []*Stack) bool {
	m := make(map[string]*Stack, len(a))
	for _, lib := range a {
		m[lib.Name] = lib
	}

	n := make(map[string]*Stack, len(b))
	for _, lib := range b {
		n[lib.Name] = lib
	}

	if len(m) != len(n) {
		return false
	}

	for id, a := range m {
		b, ok := n[id]
		if !ok {
			return false
		}
		if !a.Equal(b) {
			return false
		}
	}

	return true
}

func equalDatasources(a, b []Datasource) bool {
	if len(a) != len(b) {
		return false
	}

	m := make(map[string]Datasource, len(a))
	for _, ds := range a {
		m[ds.Name] = ds
	}

	for _, ds := range b {
		if other, ok := m[ds.Name]; !ok || !ds.Equal(&other) {
			return false
		}
	}

	return true
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
