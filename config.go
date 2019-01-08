package taask

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"os/user"
	"path"

	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"
)

// ConfigClientBadeDir is the path in $HOME where configs are stored/
const (
	ConfigClientBaseDir = ".taask/client/config/"
)

// LocalAuthConfigFromFile reads a LocalAuthConfig from a file
func LocalAuthConfigFromFile(filepath string) (*LocalAuthConfig, error) {
	raw, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to ReadFile")
	}

	config := &LocalAuthConfig{}
	if err := yaml.Unmarshal(raw, config); err != nil {
		if jsonErr := json.Unmarshal(raw, config); jsonErr != nil {
			return nil, errors.Wrap(jsonErr, errors.Wrap(err, "failed to yaml and json Unmarshal").Error()) // stupid, but whatever
		}
	}

	return config, nil
}

// DefaultConfigDir returns ~/.taask/server/config unless XDG_CONFIG_HOME is set
func DefaultConfigDir() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}

	root := u.HomeDir
	xdgConfig, useXDG := os.LookupEnv("XDG_CONFIG_HOME")
	if useXDG {
		root = xdgConfig
	}

	return path.Join(root, ConfigClientBaseDir)
}
