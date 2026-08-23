package main

import (
	"fmt"
	"io"
	"log"
	"os"

	cli "github.com/urfave/cli/v3"
)

type Config struct {
	ConfigFile    string
	CA            string
	CAPrivKey     string
	ClientID      string
	SecretKey     string
	ClientIDFile  string
	SecretKeyFile string
	PProfEnabled  bool
	BypassAuth    bool
}

func loadConfigFromCLI(cmd *cli.Command) (*Config, error) {
	cfg := &Config{
		ConfigFile:    cmd.String("config"),
		CA:            cmd.String("ca"),
		CAPrivKey:     cmd.String("ca-priv-key"),
		ClientID:      cmd.String("client-id"),
		SecretKey:     cmd.String("secret-key"),
		ClientIDFile:  cmd.String("client-id-file"),
		SecretKeyFile: cmd.String("secret-key-file"),
		PProfEnabled:  cmd.Bool("enable-pprof"),
		BypassAuth:    cmd.Bool("bypass-auth"),
	}

	// Resolve indirect file references if direct values were not provided
	if cfg.ClientID == "" && cfg.ClientIDFile != "" {
		val, err := readFileContent(cfg.ClientIDFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client_id_file '%s': %w", cfg.ClientIDFile, err)
		}
		cfg.ClientID = val
	}

	if cfg.SecretKey == "" && cfg.SecretKeyFile != "" {
		val, err := readFileContent(cfg.SecretKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read secret_key_file '%s': %w", cfg.SecretKeyFile, err)
		}
		cfg.SecretKey = val
	}

	return cfg, nil
}

func readFileContent(filepath string) (string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	bytes, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func ConfigureFromCLI(cmd *cli.Command) func(*Config) {
	return func(cfg *Config) {
		cfgFromCLI, err := loadConfigFromCLI(cmd)
		if err != nil {
			log.Fatalf("Error loading configuration from CLI: %v", err)
		}
		*cfg = *cfgFromCLI
	}
}
