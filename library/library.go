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
	OTPType      string `yaml:"otp-type"`
}

func ReadLibrary() (InformerLibrary, error) {
	dataLocation, err := dataDir()
	if err != nil {
		return InformerLibrary{}, err
	}

	libraryFile, err := ioutil.ReadFile(dataLocation)
	if err != nil {
		return InformerLibrary{}, err
	}

	library := InformerLibrary{}
	err = yaml.Unmarshal(libraryFile, &library)
	if err != nil {
		return InformerLibrary{}, err
	}

	return library, nil
}

func dataDir() (string, error) {
	dataPath := os.Getenv("XDG_DATA_HOME")
	if dataPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		dataPath = strings.Join([]string{homeDir, ".local", "share"}, string(filepath.Separator))
	}
	location := strings.Join([]string{dataPath, "informer", "libraries.yaml"}, string(filepath.Separator))

	return location, nil
}
