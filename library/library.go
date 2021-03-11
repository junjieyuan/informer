package library

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
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
	Version     string        `json:"version" yaml:"version"`
	Unlocked    bool          `json:"unlocked" yaml:"unlocked"`
	SecureStore []SecureStore `json:"libraries" yaml:"libraries"`
}

type SecureStore struct {
	ID           string `json:"id" yaml:"id"`
	Platform     string `json:"platform" yaml:"platform"`
	FriendlyName string `json:"friendlyName" yaml:"friendly-name"`
	Icon         string `json:"icon" yaml:"icon"`
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
		log.Println("Data dir not exists, creating it")
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
		for i := 0; i < len(informerLibrary.SecureStore); i++ {
			encryptedPassword, err := encrypt(key, informerLibrary.SecureStore[i].Password)
			if err != nil {
				return err
			}
			encryptedOTP, err := encrypt(key, informerLibrary.SecureStore[i].OTP)
			if err != nil {
				return err
			}

			informerLibrary.SecureStore[i].Password = encryptedPassword
			informerLibrary.SecureStore[i].OTP = encryptedOTP
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

	for i := 0; i < len(informerLibrary.SecureStore); i++ {
		decryptedPassword, err := decrypt(key, informerLibrary.SecureStore[i].Password)
		if err != nil {
			return err
		}
		decryptedOTP, err := decrypt(key, informerLibrary.SecureStore[i].OTP)
		if err != nil {
			return err
		}

		informerLibrary.SecureStore[i].Password = decryptedPassword
		informerLibrary.SecureStore[i].OTP = decryptedOTP
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

//Add SecureStore as the latest element of queue.
func (informerLibrary *InformerLibrary) Add(secure SecureStore) {
	informerLibrary.SecureStore = append(informerLibrary.SecureStore, secure)
}

//Delete SecureStore at given index.
func (informerLibrary *InformerLibrary) Remove(i int) {
	informerLibrary.SecureStore = append(informerLibrary.SecureStore[0:i], informerLibrary.SecureStore[i+1:]...)
}

//Using given SecureStore to update SecureStore that at given index.
func (informerLibrary *InformerLibrary) Update(i int, secure SecureStore) {
	informerLibrary.SecureStore[i] = secure
}

//If found, return true and indexes, else return false and nil.
func (informerLibrary InformerLibrary) Query(text string) (bool, []SecureStore) {
	text = strings.ToLower(text)
	var results []SecureStore
	found := false

	for _, secure := range informerLibrary.SecureStore {
		if strings.Contains(strings.ToLower(secure.ID), text) ||
			strings.Contains(strings.ToLower(secure.FriendlyName), text) ||
			strings.Contains(strings.ToLower(secure.Username), text) {

			found = true
			results = append(results, secure)
		}
	}

	return found, results
}

//If found, return true and index, else return false and -1.
func (informerLibrary InformerLibrary) QueryPrimaryKey(id, platform, username string) (bool, int) {
	for i, secure := range informerLibrary.SecureStore {
		if strings.EqualFold(secure.ID, id) &&
			strings.EqualFold(secure.Platform, platform) &&
			strings.EqualFold(secure.Username, username) {

			return true, i
		}
	}

	return false, -1
}

//Return all of SecureStore
func (informerLibrary InformerLibrary) List() []SecureStore {
	var results []SecureStore

	for _, secureStore := range informerLibrary.SecureStore {
		results = append(results, secureStore)
	}

	return results
}
