package main

import (
	"context"
	"fmt"
	"io"
	"os"

	altsrc "github.com/urfave/cli-altsrc/v3"
	jsonaltsrc "github.com/urfave/cli-altsrc/v3/json"
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

func buildCLIApp(actionFunc func(ctx context.Context, cmd *cli.Command) error) *cli.Command {
	var configFilePath string

	jsonSourcer := altsrc.NewStringPtrSourcer(&configFilePath)

	jsonValSrc := func(keyPath string) cli.ValueSource {
		return jsonaltsrc.JSON(keyPath, jsonSourcer)
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
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			if cmd.IsSet("config") {
				if _, err := os.Stat(configFilePath); err != nil {
					return ctx, fmt.Errorf("config file '%s' not found: %w", configFilePath, err)
				}
			} else if configFilePath == "" {
				defaultPath := "server/nopush/config.json"
				if _, err := os.Stat(defaultPath); err == nil {
					configFilePath = defaultPath
				}
			}
			return ctx, nil
		},
		Action: actionFunc,
	}
}
