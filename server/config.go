package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"
)

type FileConfig struct {
	Certificates struct {
		CA        string `json:"ca"`
		CAPrivKey string `json:"ca_priv_key"`
	} `json:"certificates"`
	OAuth struct {
		ClientIDFile  string `json:"client_id_file"`
		SecretKeyFile string `json:"secret_key_file"`
	} `json:"oauth"`
	PProfEnabled bool `json:"enable_pprof,omitempty"`
	BypassAuth   bool `json:"bypass_auth,omitempty"`
}

type Config struct {
	CA           string
	CAPrivKey    string
	ClientID     string
	SecretKey    string
	PProfEnabled bool
	BypassAuth   bool
}

func configureFromFile(fileName string) func(*Config) {
	return func(cfg *Config) {
		f, err := os.Open(fileName)
		if err != nil {
			log.Fatalf("Failed to open config file '%s': %v", fileName, err)
		}
		defer f.Close()

		jsonBytes, err := ioutil.ReadAll(f)
		if err != nil {
			log.Fatalf("Failed to read config file '%s': %v", fileName, err)
		}

		fileCFG := &FileConfig{}
		err = json.Unmarshal(jsonBytes, fileCFG)
		if err != nil {
			log.Fatalf("Failed to parse config file '%s': %v", fileName, err)
		}

		cfg.PProfEnabled = fileCFG.PProfEnabled
		cfg.BypassAuth = fileCFG.BypassAuth

		f, err = os.Open(fileCFG.OAuth.ClientIDFile)
		if err != nil {
			log.Fatalf("Failed to open configured client_id_file '%s': %v", fileCFG.OAuth.ClientIDFile, err)
		}
		defer f.Close()
		clientIDBytes, err := io.ReadAll(f)
		if err != nil {
			log.Fatalf("Failed to read configured client_id_file '%s': %v", fileCFG.OAuth.ClientIDFile, err)
		}
		clientID := string(clientIDBytes)
		cfg.ClientID = clientID

		f, err = os.Open(fileCFG.OAuth.SecretKeyFile)
		if err != nil {
			log.Fatalf("Failed to open configured secret_key_file '%s': %v", fileCFG.OAuth.SecretKeyFile, err)
		}
		defer f.Close()
		secretKeyBytes, err := io.ReadAll(f)
		if err != nil {
			log.Fatalf("Failed to read configured secret_key_file '%s': %v", fileCFG.OAuth.SecretKeyFile, err)
		}
		secretKey := string(secretKeyBytes)
		cfg.SecretKey = secretKey
	}
}
