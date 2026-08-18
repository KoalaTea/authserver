package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v3"
)

type FileConfig struct {
	Certificates struct {
		CA        string `json:"ca"`
		CAPrivKey string `json:"ca_priv_key"`
	} `json:"certificates"`
	OAuth struct {
		ClientID      string `json:"client_id"`
		SecretKey     string `json:"secret_key"`
		ClientIDFile  string `json:"client_id_file"`
		SecretKeyFile string `json:"secret_key_file"`
	} `json:"oauth"`
	PProfEnabled bool `json:"enable_pprof,omitempty"`
	BypassAuth   bool `json:"bypass_auth,omitempty"`
}

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

	// Step 1: Fallback loading from JSON config file if present
	configFileToLoad := cfg.ConfigFile
	if configFileToLoad == "" {
		if _, err := os.Stat("server/nopush/config.json"); err == nil {
			configFileToLoad = "server/nopush/config.json"
		}
	}

	if configFileToLoad != "" {
		fileBytes, err := os.ReadFile(configFileToLoad)
		if err != nil {
			if cmd.IsSet("config") {
				return nil, fmt.Errorf("config file '%s' not found: %w", configFileToLoad, err)
			}
		} else {
			var fileCFG FileConfig
			if err := json.Unmarshal(fileBytes, &fileCFG); err != nil {
				return nil, fmt.Errorf("failed to parse config file '%s': %w", configFileToLoad, err)
			}

			if !cmd.IsSet("ca") && cfg.CA == "" && fileCFG.Certificates.CA != "" {
				cfg.CA = fileCFG.Certificates.CA
			}
			if !cmd.IsSet("ca-priv-key") && cfg.CAPrivKey == "" && fileCFG.Certificates.CAPrivKey != "" {
				cfg.CAPrivKey = fileCFG.Certificates.CAPrivKey
			}
			if !cmd.IsSet("client-id") && cfg.ClientID == "" && fileCFG.OAuth.ClientID != "" {
				cfg.ClientID = fileCFG.OAuth.ClientID
			}
			if !cmd.IsSet("secret-key") && cfg.SecretKey == "" && fileCFG.OAuth.SecretKey != "" {
				cfg.SecretKey = fileCFG.OAuth.SecretKey
			}
			if !cmd.IsSet("client-id-file") && cfg.ClientIDFile == "" && fileCFG.OAuth.ClientIDFile != "" {
				cfg.ClientIDFile = fileCFG.OAuth.ClientIDFile
			}
			if !cmd.IsSet("secret-key-file") && cfg.SecretKeyFile == "" && fileCFG.OAuth.SecretKeyFile != "" {
				cfg.SecretKeyFile = fileCFG.OAuth.SecretKeyFile
			}
			if !cmd.IsSet("enable-pprof") && !cfg.PProfEnabled {
				cfg.PProfEnabled = fileCFG.PProfEnabled
			}
			if !cmd.IsSet("bypass-auth") && !cfg.BypassAuth {
				cfg.BypassAuth = fileCFG.BypassAuth
			}
		}
	}

	// Step 2: Resolve indirect file references if direct values were not provided
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

func buildCLIApp(actionFunc func(ctx context.Context, cmd *cli.Command) error) *cli.Command {
	return &cli.Command{
		Name:  "authserver",
		Usage: "Authentication Server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "path to JSON config file",
				Sources: cli.EnvVars("AUTH_CONFIG", "CONFIG_FILE"),
			},
			&cli.StringFlag{
				Name:    "ca",
				Usage:   "Certificate Authority certificate string or path",
				Sources: cli.EnvVars("AUTH_CA"),
			},
			&cli.StringFlag{
				Name:    "ca-priv-key",
				Usage:   "Certificate Authority private key string or path",
				Sources: cli.EnvVars("AUTH_CA_PRIV_KEY"),
			},
			&cli.StringFlag{
				Name:    "client-id",
				Usage:   "OAuth Client ID",
				Sources: cli.EnvVars("AUTH_CLIENT_ID"),
			},
			&cli.StringFlag{
				Name:    "secret-key",
				Usage:   "OAuth Secret Key",
				Sources: cli.EnvVars("AUTH_SECRET_KEY"),
			},
			&cli.StringFlag{
				Name:    "client-id-file",
				Usage:   "Path to file containing OAuth Client ID",
				Sources: cli.EnvVars("AUTH_CLIENT_ID_FILE"),
			},
			&cli.StringFlag{
				Name:    "secret-key-file",
				Usage:   "Path to file containing OAuth Secret Key",
				Sources: cli.EnvVars("AUTH_SECRET_KEY_FILE"),
			},
			&cli.BoolFlag{
				Name:    "enable-pprof",
				Usage:   "Enable performance profiling (pprof)",
				Sources: cli.EnvVars("AUTH_ENABLE_PPROF"),
			},
			&cli.BoolFlag{
				Name:    "bypass-auth",
				Usage:   "Bypass authentication requirements",
				Sources: cli.EnvVars("AUTH_BYPASS_AUTH"),
			},
		},
		Action: actionFunc,
	}
}
