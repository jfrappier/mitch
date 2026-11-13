package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/jfrappier/mitch/internal/checks"
)

// scanRootOnlyChecks runs the checks Vault only serves from the root
// namespace: configuration, version history, plugins, and the sudo checks.
func (s *Scanner) scanRootOnlyChecks(ctx context.Context) error {
	steps := []func(context.Context) error{
		s.readConfig,
		s.readVersionHistory,
		s.readPlugins,
		s.readPluginDetails,
		s.readPluginRuntimes,
		s.readAuditDevices,
	}

	for _, step := range steps {
		err := step(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

// readConfig calls GET sys/config/state/sanitized and keeps the result as-is.
func (s *Scanner) readConfig(ctx context.Context) error {
	if !s.beginCheck(checks.CheckConfig, "") {
		return nil
	}

	response, err := s.client.Read(ctx, "read_config", "", "sys/config/state/sanitized")
	if err != nil {
		return s.handleFailure(checks.CheckConfig, "", err)
	}

	s.inventory.Config = response.Data
	return nil
}

// readVersionHistory calls LIST sys/version-history.
func (s *Scanner) readVersionHistory(ctx context.Context) error {
	if !s.beginCheck(checks.CheckVersionHistory, "") {
		return nil
	}

	response, err := s.client.List(ctx, "list_version_history", "", "sys/version-history")
	if err != nil {
		return s.handleFailure(checks.CheckVersionHistory, "", err)
	}

	var parsed struct {
		Keys    []string `json:"keys"`
		KeyInfo map[string]struct {
			BuildDate          string  `json:"build_date"`
			PreviousVersion    *string `json:"previous_version"`
			TimestampInstalled string  `json:"timestamp_installed"`
		} `json:"key_info"`
	}
	err = json.Unmarshal(response.Data, &parsed)
	if err != nil {
		return fmt.Errorf("sys/version-history returned unexpected JSON: %w", err)
	}

	for _, versionKey := range parsed.Keys {
		info := parsed.KeyInfo[versionKey]

		previousVersion := ""
		if info.PreviousVersion != nil {
			previousVersion = *info.PreviousVersion
		}

		s.inventory.VersionHistory = append(s.inventory.VersionHistory, VersionHistoryEntry{
			Version:            versionKey,
			BuildDate:          info.BuildDate,
			PreviousVersion:    previousVersion,
			TimestampInstalled: info.TimestampInstalled,
		})
	}
	return nil
}

// readPlugins calls GET sys/plugins/catalog and keeps the "detailed" list,
// which says whether each plugin is built in.
func (s *Scanner) readPlugins(ctx context.Context) error {
	if !s.beginCheck(checks.CheckPlugins, "") {
		return nil
	}

	response, err := s.client.Read(ctx, "list_plugins", "", "sys/plugins/catalog")
	if err != nil {
		return s.handleFailure(checks.CheckPlugins, "", err)
	}

	var parsed struct {
		Detailed []Plugin `json:"detailed"`
	}
	err = json.Unmarshal(response.Data, &parsed)
	if err != nil {
		return fmt.Errorf("sys/plugins/catalog returned unexpected JSON: %w", err)
	}

	s.inventory.Plugins = parsed.Detailed
	return nil
}

// readPluginDetails (sudo) calls GET sys/plugins/catalog/:type/:name for each
// registered plugin, to record its sha256, command and args. Built-in plugins
// are skipped because they are compiled into Vault.
func (s *Scanner) readPluginDetails(ctx context.Context) error {
	if !s.beginCheck(checks.CheckPluginDetails, "") {
		return nil
	}

	for index := range s.inventory.Plugins {
		plugin := &s.inventory.Plugins[index]
		if plugin.Builtin {
			continue
		}

		path := "sys/plugins/catalog/" + url.PathEscape(plugin.Type) + "/" + url.PathEscape(plugin.Name)

		query := url.Values{}
		if plugin.Version != "" {
			query.Set("version", plugin.Version)
		}

		response, err := s.client.ReadWithQuery(ctx, "read_plugin_details", "", path, query)
		if err != nil {
			handled := s.handleFailure(checks.CheckPluginDetails, "", err)
			if handled != nil {
				return handled
			}
			continue
		}

		var details struct {
			SHA256  string   `json:"sha256"`
			Command string   `json:"command"`
			Args    []string `json:"args"`
		}
		err = json.Unmarshal(response.Data, &details)
		if err != nil {
			return fmt.Errorf("%s returned unexpected JSON: %w", path, err)
		}

		plugin.SHA256 = details.SHA256
		plugin.Command = details.Command
		plugin.Args = details.Args
	}
	return nil
}

// readPluginRuntimes (sudo) calls LIST sys/plugins/runtimes/catalog.
func (s *Scanner) readPluginRuntimes(ctx context.Context) error {
	if !s.beginCheck(checks.CheckPluginRuntimes, "") {
		return nil
	}

	response, err := s.client.List(ctx, "list_plugin_runtimes", "", "sys/plugins/runtimes/catalog")
	if err != nil {
		return s.handleFailure(checks.CheckPluginRuntimes, "", err)
	}

	var parsed struct {
		Runtimes []json.RawMessage `json:"runtimes"`
	}
	err = json.Unmarshal(response.Data, &parsed)
	if err != nil {
		return fmt.Errorf("sys/plugins/runtimes/catalog returned unexpected JSON: %w", err)
	}

	// Record an empty list, not null, so the output shows the check ran.
	s.inventory.PluginRuntimes = []json.RawMessage{}
	s.inventory.PluginRuntimes = append(s.inventory.PluginRuntimes, parsed.Runtimes...)
	return nil
}

// readAuditDevices (sudo) calls GET sys/audit.
func (s *Scanner) readAuditDevices(ctx context.Context) error {
	if !s.beginCheck(checks.CheckAuditDevices, "") {
		return nil
	}

	response, err := s.client.Read(ctx, "list_audit_devices", "", "sys/audit")
	if err != nil {
		return s.handleFailure(checks.CheckAuditDevices, "", err)
	}

	var devicesByPath map[string]AuditDevice
	err = json.Unmarshal(response.Data, &devicesByPath)
	if err != nil {
		return fmt.Errorf("sys/audit returned unexpected JSON: %w", err)
	}

	s.inventory.AuditDevices = []AuditDevice{}
	for _, devicePath := range sortedKeys(devicesByPath) {
		device := devicesByPath[devicePath]
		device.Path = devicePath
		s.inventory.AuditDevices = append(s.inventory.AuditDevices, device)
	}
	return nil
}
