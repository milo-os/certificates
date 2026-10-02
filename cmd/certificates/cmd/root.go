// SPDX-License-Identifier: AGPL-3.0-only

// Package cmd contains the cobra command definitions for the certificates binary.
package cmd

import "github.com/spf13/cobra"

// BuildInfo carries version metadata injected at build time via -ldflags.
type BuildInfo struct {
	Version      string
	GitCommit    string
	GitTreeState string
	BuildDate    string
}

// NewRootCommand returns the certificates root cobra command.
// It has no RunE — invoking 'certificates' with no subcommand prints help.
func NewRootCommand(info BuildInfo) *cobra.Command {
	root := &cobra.Command{
		Use:   "certificates",
		Short: "Milo control plane controller template",
		// No RunE — 'certificates' with no subcommand prints help.
	}
	root.AddCommand(newOperatorCommand(info))
	return root
}
