package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type config struct {
	Certificates struct {
		CA        string `json:"ca"`
		CAPrivKey string `json:"ca_priv_key"`
	} `json:"certificates"`
	OAuth struct {
		ClientID  string `json:"client_id"`
		SecretKey string `json:"secret_key`
	} `json:"oauth"`
}

type Config {
	CA string
	CAPrivKey string
	ClientID string
	SecretKey string
}

func get_config(fileName string) *Config {
	f, err := os.Open(fileName)
	if err != nil {
		fmt.Errorf("%w", err)
	}
	defer f.Close()

	jsonBytes, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Errorf("%w", err)
	}

	cfg := &Config{}
	err = json.Unmarshal(jsonBytes, cfg)
	if err != nil {
		fmt.Errorf("%w", err)
	}

	f, err = os.Open(cfg.Oauth.ClientID)
	if err != nil {
		fmt.Errorf("%w", err)
	}
	defer f.Close()
	clientIDBytes, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Errorf("%w", err)
	}
	clientID := string(clientIDBytes)

	f, err = os.Open(cfg.Oauth.SecretKey)
	if err != nil {
		fmt.Errorf("%w", err)
	}
	defer f.Close()
	secretKeyBytes, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Errorf("%w", err)
	}
	secretKey := string(secretKeyBytes)

	return &Config{CA: "", CAPrivKey: "", ClientID: clientID, SecretKey: secretKey}
}
