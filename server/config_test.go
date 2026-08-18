package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func TestConfigFromCLI(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		app := buildCLIApp(func(ctx context.Context, cmd *cli.Command) error {
			cfg, err := loadConfigFromCLI(cmd)
			require.NoError(t, err)
			assert.Equal(t, "", cfg.ClientID)
			assert.Equal(t, "", cfg.SecretKey)
			assert.False(t, cfg.PProfEnabled)
			assert.False(t, cfg.BypassAuth)
			return nil
		})
		err := app.Run(context.Background(), []string{"authserver"})
		require.NoError(t, err)
	})

	t.Run("flags override", func(t *testing.T) {
		app := buildCLIApp(func(ctx context.Context, cmd *cli.Command) error {
			cfg, err := loadConfigFromCLI(cmd)
			require.NoError(t, err)
			assert.Equal(t, "flag-client-id", cfg.ClientID)
			assert.Equal(t, "flag-secret-key", cfg.SecretKey)
			assert.True(t, cfg.PProfEnabled)
			assert.True(t, cfg.BypassAuth)
			return nil
		})
		err := app.Run(context.Background(), []string{
			"authserver",
			"--client-id", "flag-client-id",
			"--secret-key", "flag-secret-key",
			"--enable-pprof",
			"--bypass-auth",
		})
		require.NoError(t, err)
	})

	t.Run("env vars override", func(t *testing.T) {
		t.Setenv("AUTH_CLIENT_ID", "env-client-id")
		t.Setenv("AUTH_SECRET_KEY", "env-secret-key")
		t.Setenv("AUTH_ENABLE_PPROF", "true")
		t.Setenv("AUTH_BYPASS_AUTH", "true")

		app := buildCLIApp(func(ctx context.Context, cmd *cli.Command) error {
			cfg, err := loadConfigFromCLI(cmd)
			require.NoError(t, err)
			assert.Equal(t, "env-client-id", cfg.ClientID)
			assert.Equal(t, "env-secret-key", cfg.SecretKey)
			assert.True(t, cfg.PProfEnabled)
			assert.True(t, cfg.BypassAuth)
			return nil
		})
		err := app.Run(context.Background(), []string{"authserver"})
		require.NoError(t, err)
	})

	t.Run("config file loading", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.json")
		jsonContent := `{
			"oauth": {
				"client_id": "json-client-id",
				"secret_key": "json-secret-key"
			},
			"enable_pprof": true,
			"bypass_auth": true
		}`
		err := os.WriteFile(configFile, []byte(jsonContent), 0644)
		require.NoError(t, err)

		app := buildCLIApp(func(ctx context.Context, cmd *cli.Command) error {
			cfg, err := loadConfigFromCLI(cmd)
			require.NoError(t, err)
			assert.Equal(t, "json-client-id", cfg.ClientID)
			assert.Equal(t, "json-secret-key", cfg.SecretKey)
			assert.True(t, cfg.PProfEnabled)
			assert.True(t, cfg.BypassAuth)
			return nil
		})
		err = app.Run(context.Background(), []string{"authserver", "--config", configFile})
		require.NoError(t, err)
	})

	t.Run("client_id_file and secret_key_file in config", func(t *testing.T) {
		tmpDir := t.TempDir()
		idFile := filepath.Join(tmpDir, "client_id.txt")
		keyFile := filepath.Join(tmpDir, "secret_key.txt")
		require.NoError(t, os.WriteFile(idFile, []byte("file-client-id"), 0644))
		require.NoError(t, os.WriteFile(keyFile, []byte("file-secret-key"), 0644))

		configFile := filepath.Join(tmpDir, "config.json")
		jsonContent := `{
			"oauth": {
				"client_id_file": "` + idFile + `",
				"secret_key_file": "` + keyFile + `"
			}
		}`
		require.NoError(t, os.WriteFile(configFile, []byte(jsonContent), 0644))

		app := buildCLIApp(func(ctx context.Context, cmd *cli.Command) error {
			cfg, err := loadConfigFromCLI(cmd)
			require.NoError(t, err)
			assert.Equal(t, "file-client-id", cfg.ClientID)
			assert.Equal(t, "file-secret-key", cfg.SecretKey)
			return nil
		})
		err := app.Run(context.Background(), []string{"authserver", "--config", configFile})
		require.NoError(t, err)
	})

	t.Run("flags override config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.json")
		jsonContent := `{
			"oauth": {
				"client_id": "json-client-id",
				"secret_key": "json-secret-key"
			},
			"enable_pprof": false
		}`
		require.NoError(t, os.WriteFile(configFile, []byte(jsonContent), 0644))

		app := buildCLIApp(func(ctx context.Context, cmd *cli.Command) error {
			cfg, err := loadConfigFromCLI(cmd)
			require.NoError(t, err)
			assert.Equal(t, "override-client-id", cfg.ClientID)
			assert.Equal(t, "json-secret-key", cfg.SecretKey)
			assert.True(t, cfg.PProfEnabled)
			return nil
		})
		err := app.Run(context.Background(), []string{
			"authserver",
			"--config", configFile,
			"--client-id", "override-client-id",
			"--enable-pprof",
		})
		require.NoError(t, err)
	})
}
