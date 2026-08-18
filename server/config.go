package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli-altsrc/v3"
	"github.com/urfave/cli/v3"
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

type fileConfigJSON struct {
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

	// Step 1: Fallback loading from JSON config file if flags were not set
	configFileToLoad := cfg.ConfigFile
	if configFileToLoad == "" {
		if _, err := os.Stat("server/nopush/config.json"); err == nil {
			configFileToLoad = "server/nopush/config.json"
		}
	}

	if configFileToLoad != "" {
		if fileBytes, err := os.ReadFile(configFileToLoad); err == nil {
			var fileCFG fileConfigJSON
			if err := json.Unmarshal(fileBytes, &fileCFG); err == nil {
				if !cmd.IsSet("ca") && fileCFG.Certificates.CA != "" {
					cfg.CA = fileCFG.Certificates.CA
				}
				if !cmd.IsSet("ca-priv-key") && fileCFG.Certificates.CAPrivKey != "" {
					cfg.CAPrivKey = fileCFG.Certificates.CAPrivKey
				}
				if !cmd.IsSet("client-id") && fileCFG.OAuth.ClientID != "" {
					cfg.ClientID = fileCFG.OAuth.ClientID
				}
				if !cmd.IsSet("secret-key") && fileCFG.OAuth.SecretKey != "" {
					cfg.SecretKey = fileCFG.OAuth.SecretKey
				}
				if !cmd.IsSet("client-id-file") && fileCFG.OAuth.ClientIDFile != "" {
					cfg.ClientIDFile = fileCFG.OAuth.ClientIDFile
				}
				if !cmd.IsSet("secret-key-file") && fileCFG.OAuth.SecretKeyFile != "" {
					cfg.SecretKeyFile = fileCFG.OAuth.SecretKeyFile
				}
				if !cmd.IsSet("enable-pprof") {
					cfg.PProfEnabled = fileCFG.PProfEnabled
				}
				if !cmd.IsSet("bypass-auth") {
					cfg.BypassAuth = fileCFG.BypassAuth
				}
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
	var configFilePath string

	jsonUnmarshaler := func(b []byte, v any) error {
		return json.Unmarshal(b, v)
	}

	jsonSourcer := altsrc.NewStringPtrSourcer(&configFilePath)

	jsonValSrc := func(keyPath string) cli.ValueSource {
		return altsrc.NewValueSource(jsonUnmarshaler, "json config file", keyPath, jsonSourcer)
	}

	return &cli.Command{
		Name:  "authserver",
		Usage: "Authentication Server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "config",
				Aliases:     []string{"c"},
				Usage:       "path to JSON config file",
				Destination: &configFilePath,
				Sources:     cli.EnvVars("AUTH_CONFIG", "CONFIG_FILE"),
			},
			&cli.StringFlag{
				Name:    "ca",
				Usage:   "Certificate Authority certificate string or path",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_CA"), jsonValSrc("certificates.ca")),
			},
			&cli.StringFlag{
				Name:    "ca-priv-key",
				Usage:   "Certificate Authority private key string or path",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_CA_PRIV_KEY"), jsonValSrc("certificates.ca_priv_key")),
			},
			&cli.StringFlag{
				Name:    "client-id",
				Usage:   "OAuth Client ID",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_CLIENT_ID"), jsonValSrc("oauth.client_id")),
			},
			&cli.StringFlag{
				Name:    "secret-key",
				Usage:   "OAuth Secret Key",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_SECRET_KEY"), jsonValSrc("oauth.secret_key")),
			},
			&cli.StringFlag{
				Name:    "client-id-file",
				Usage:   "Path to file containing OAuth Client ID",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_CLIENT_ID_FILE"), jsonValSrc("oauth.client_id_file")),
			},
			&cli.StringFlag{
				Name:    "secret-key-file",
				Usage:   "Path to file containing OAuth Secret Key",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_SECRET_KEY_FILE"), jsonValSrc("oauth.secret_key_file")),
			},
			&cli.BoolFlag{
				Name:    "enable-pprof",
				Usage:   "Enable performance profiling (pprof)",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_ENABLE_PPROF"), jsonValSrc("enable_pprof")),
			},
			&cli.BoolFlag{
				Name:    "bypass-auth",
				Usage:   "Bypass authentication requirements",
				Sources: cli.NewValueSourceChain(cli.EnvVar("AUTH_BYPASS_AUTH"), jsonValSrc("bypass_auth")),
			},
		},
		Action: actionFunc,
	}
}
