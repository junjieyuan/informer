package conf

import (
	"encoding/hex"
	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type InformerConfig struct {
	Version      string `yaml:"version"`
	RenewalCycle int    `yaml:"renewal-cycle"`
	Port         string `yaml:"port"`
	User         User   `yaml:"user"`
}

type User struct {
	Username string  `json:"username" yaml:"username"`
	Password string  `json:"password" yaml:"password"`
	Tokens   []Token `json:"tokens" yaml:"tokens"`
}

type Token struct {
	ID         string    `json:"id" yaml:"id"`
	CreateDate time.Time `json:"create-date" yaml:"create-date"`
}

func ReadConfig() (InformerConfig, error) {
	configLocation, err := configPath()
	informerConfig := InformerConfig{}

	if err != nil {
		return informerConfig, err
	}

	configFile, err := ioutil.ReadFile(configLocation)
	if err != nil {
		return informerConfig, err
	}

	err = yaml.Unmarshal(configFile, &informerConfig)
	if err != nil {
		return InformerConfig{}, err
	}

	return informerConfig, nil
}

func (informerConfig InformerConfig) WriteConfig() error {
	dataLocation, err := configPath()
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(informerConfig)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dataLocation, data, os.FileMode(0600))
	if err != nil {
		return err
	}

	return nil
}

func (informerConfig InformerConfig) CheckUser(user User) bool {
	//covert [N]byte to []byte, then covert []byte to hex string, same as sha3sum command
	digest := sha3.Sum512([]byte(user.Password))
	user.Password = hex.EncodeToString(digest[:])

	if informerConfig.User.Username == user.Username && informerConfig.User.Password == user.Password {
		return true
	}

	return false
}

func (informerConfig InformerConfig) CheckLogin(username string, token string) bool {
	if informerConfig.User.Username == username {
		for _, knownToken := range informerConfig.User.Tokens {
			if knownToken.ID == token {
				expireDate := knownToken.CreateDate.AddDate(0, 0, informerConfig.RenewalCycle)
				if expireDate.After(time.Now()) {
					return true
				}
			}
		}
	}

	return false
}

func (user *User) AddToken(token Token) {
	user.Tokens = append(user.Tokens, token)
}

func configPath() (string, error) {
	configPath := os.Getenv("XDG_CONFIG_HOME")
	if configPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		configPath = strings.Join([]string{homeDir, ".config"}, string(filepath.Separator))
	}
	location := strings.Join([]string{configPath, "informer", "config.yaml"}, string(filepath.Separator))

	return location, nil
}

func GenerateToken() string {
	return uuid.NewString()
}

func (informerConfig *InformerConfig) ChangePassword(newUser User) {
	if informerConfig.User.Username == newUser.Username {
		//covert [N]byte to []byte, then covert []byte to hex string, same as sha3sum command
		digest := sha3.Sum512([]byte(newUser.Password))
		informerConfig.User.Password = hex.EncodeToString(digest[:])
		informerConfig.User.Tokens = nil
	}
}
