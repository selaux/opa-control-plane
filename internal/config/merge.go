package config

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func Merge(configFiles []string) ([]byte, error) {

	var paths []string
	for _, f := range configFiles {
		filepath.Walk(f, func(path string, fi fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}
			paths = append(paths, path)
			return nil
		})
	}

	var docs []map[string]interface{}
	for _, f := range paths {
		bs, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("failed to read configuration file %v: %v", f, err)
		}
		var x map[string]interface{}
		if err := yaml.Unmarshal(bs, &x); err != nil {
			return nil, fmt.Errorf("failed to unmarshal configuration file %v: %v", f, err)
		}
		docs = append(docs, x)
	}

	merged := merge(docs)
	bs, err := yaml.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal merged configuration: %v", err)
	}

	return bs, nil
}

func merge(docs []map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, doc := range docs {
		for key, value := range doc {
			if existing, ok := result[key]; ok {
				if existingMap, ok1 := existing.(map[string]interface{}); ok1 {
					if valueMap, ok2 := value.(map[string]interface{}); ok2 {
						result[key] = merge([]map[string]interface{}{existingMap, valueMap})
						continue
					}
				}
			}
			result[key] = value
		}
	}
	return result
}
