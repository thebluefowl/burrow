package main

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "burrow",
	Short: "Backblaze B2 backup tool with encryption",
	Long:  `A CLI tool for securely backing up files to Backblaze B2 with encryption`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(uploadCmd)
	rootCmd.AddCommand(downloadCmd)
}
