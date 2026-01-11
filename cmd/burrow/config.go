package main

import (
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
	Long:  `Manage your Backblaze B2 configuration settings.`,
}

func init() {
	configCmd.AddCommand(updateCmd)
}
