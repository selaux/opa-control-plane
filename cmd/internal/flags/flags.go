package flags

import "github.com/spf13/pflag"

func AddConfig(fs *pflag.FlagSet, x *[]string) {
	fs.StringSliceVarP(x, "config", "c", []string{"config.d"}, "Path to the configuration (file or directory)")
}
