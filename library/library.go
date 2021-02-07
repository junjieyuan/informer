package library

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

type InformerLibrary struct {
	Version     string        `yaml:"version"`
	SecureStore []SecureStore `yaml:"libraries"`
}

type SecureStore struct {
	ID           string `yaml:"id"`
	Platform     string `yaml:"platform"`
	FriendlyName string `yaml:"friendly-name"`
	Icon         string `yaml:"icon"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	OTP          string `yaml:"otp"`
}

func ReadLibrary() (InformerLibrary, error) {
	dataPath := os.Getenv("XDG_DATA_HOME")
	if dataPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return InformerLibrary{}, err
		}

		dataPath = strings.Join([]string{homeDir, ".local", "share"}, string(filepath.Separator))
	}
	location := strings.Join([]string{dataPath, "informer", "libraries.yaml"}, string(filepath.Separator))

	library := InformerLibrary{}
	err := readLibrary(location, &library)
	if err != nil {
		return InformerLibrary{}, err
	}

	return library, err
}

func readLibrary(location string, library *InformerLibrary) error {
	libraryFile, err := ioutil.ReadFile(location)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(libraryFile, library)
	if err != nil {
		return err
	}

	return err
}
