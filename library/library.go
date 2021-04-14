package library

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"github.com/google/uuid"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

var (
	dataDefault = InformerLibrary{Version: "0.1", Unlocked: true}
)

type InformerLibrary struct {
	Version     string                  `json:"version" yaml:"version"`
	Unlocked    bool                    `json:"unlocked" yaml:"unlocked"`
	SecureStore map[string]*SecureStore `json:"libraries" yaml:"libraries"`
}

type SecureStore struct {
	ID           string `json:"id" yaml:"id"`
	Platform     string `json:"platform" yaml:"platform"`
	FriendlyName string `json:"friendlyName" yaml:"friendly-name"`
	Username     string `json:"username" yaml:"username"`
	Password     string `json:"password" yaml:"password"`
	OTP          string `json:"otp" yaml:"otp"`
	OTPType      string `json:"otpType" yaml:"otp-type"`
}

func ReadLibrary() (InformerLibrary, error) {
	dataLocation, err := dataPath()
	if err != nil {
		return InformerLibrary{}, err
	}
	dataDir := filepath.Dir(dataLocation)

	//If data directory doesn't exists, create it
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		log.Println("Data directory not exists, creating it")
		err = os.MkdirAll(dataDir, 0755)
		if err != nil {
			return InformerLibrary{}, err
		}
	}
	//If data file doesn't not exists, return default data
	if _, err := os.Stat(dataLocation); os.IsNotExist(err) {
		log.Println("Data file not exists, using default data")
		return dataDefault, nil
	}

	libraryFile, err := ioutil.ReadFile(dataLocation)
	if err != nil {
		return InformerLibrary{}, err
	}

	informerLibrary := InformerLibrary{}
	err = yaml.Unmarshal(libraryFile, &informerLibrary)
	if err != nil {
		return InformerLibrary{}, err
	}

	if informerLibrary.SecureStore == nil {
		informerLibrary.SecureStore = map[string]*SecureStore{}
	}

	return informerLibrary, nil
}

func (informerLibrary InformerLibrary) WriteLibrary() error {
	dataLocation, err := dataPath()
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(informerLibrary)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dataLocation, data, os.FileMode(0600))
	if err != nil {
		return err
	}

	return nil
}

func dataPath() (string, error) {
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

func (informerLibrary *InformerLibrary) Lock(key []byte) error {
	if informerLibrary.Unlocked {
		for k, v := range informerLibrary.SecureStore {
			encryptedPassword, err := encrypt(key, v.Password)
			if err != nil {
				return err
			}
			encryptedOTP, err := encrypt(key, v.OTP)
			if err != nil {
				return err
			}

			informerLibrary.SecureStore[k].Password = encryptedPassword
			informerLibrary.SecureStore[k].OTP = encryptedOTP
		}
		informerLibrary.Unlocked = false
		return nil
	}

	return nil
}

func (informerLibrary *InformerLibrary) Unlock(key []byte) error {
	if informerLibrary.Unlocked {
		return nil
	}

	for k, v := range informerLibrary.SecureStore {
		decryptedPassword, err := decrypt(key, v.Password)
		if err != nil {
			return err
		}
		decryptedOTP, err := decrypt(key, v.OTP)
		if err != nil {
			return err
		}

		informerLibrary.SecureStore[k].Password = decryptedPassword
		informerLibrary.SecureStore[k].OTP = decryptedOTP
	}

	informerLibrary.Unlocked = true

	return nil
}

func encrypt(key []byte, plainMessage string) (cipherMessage string, err error) {
	plainText := []byte(plainMessage)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherMessage = base64.StdEncoding.EncodeToString(aesGCM.Seal(nonce, nonce, plainText, nil))

	return
}

func decrypt(key []byte, encryptedMessage string) (decryptedMessage string, err error) {
	cipherText, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce, cipherText := cipherText[:aesGCM.NonceSize()], cipherText[aesGCM.NonceSize():]

	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	decryptedMessage = string(plainText)

	return
}

//Add SecureStore.
func (informerLibrary *InformerLibrary) Add(secure SecureStore) {
	k := uuid.NewString()
	informerLibrary.SecureStore[k] = &secure
}

// Remove Delete SecureStore.
func (informerLibrary *InformerLibrary) Remove(k string) {
	delete(informerLibrary.SecureStore, k)
}

// Update Using given SecureStore to update specified SecureStore.
func (informerLibrary *InformerLibrary) Update(k string, secure SecureStore) {
	informerLibrary.SecureStore[k] = &secure
}

// Query If found, return true and map of primary key and SecureStore, else return false and nil.
func (informerLibrary InformerLibrary) Query(text string) (bool, map[string]SecureStore) {
	text = strings.ToLower(text)
	results := map[string]SecureStore{}
	found := false

	for k, secure := range informerLibrary.SecureStore {
		if strings.Contains(strings.ToLower(secure.ID), text) ||
			strings.Contains(strings.ToLower(secure.FriendlyName), text) ||
			strings.Contains(strings.ToLower(secure.Username), text) {

			found = true
			results[k] = *secure
		}
	}

	return found, results
}

// List Return all of SecureStore.
func (informerLibrary InformerLibrary) List() map[string]SecureStore {
	results := map[string]SecureStore{}

	for k, v := range informerLibrary.SecureStore {
		results[k] = *v
	}

	return results
}
