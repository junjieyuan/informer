package library

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

type InformerLibrary struct {
	Version     string        `yaml:"version"`
	Unlocked    bool          `yaml:"unlocked"`
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
	dataLocation, err := dataPath()
	if err != nil {
		return InformerLibrary{}, err
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
				panic(err.Error())
			}
			encryptedOTP, err := encrypt(key, informerLibrary.SecureStore[i].OTP)
			if err != nil {
				panic(err.Error())
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
			panic(err.Error())
		}
		decryptedOTP, err := decrypt(key, informerLibrary.SecureStore[i].OTP)
		if err != nil {
			panic(err.Error())
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
		panic(err.Error())
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	cipherMessage = base64.StdEncoding.EncodeToString(aesGCM.Seal(nonce, nonce, plainText, nil))

	return
}

func decrypt(key []byte, encryptedMessage string) (decryptedMessage string, err error) {
	cipherText, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		panic(err.Error())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonce, cipherText := cipherText[:aesGCM.NonceSize()], cipherText[aesGCM.NonceSize():]

	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	decryptedMessage = string(plainText)

	return
}
