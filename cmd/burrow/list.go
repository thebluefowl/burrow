package main

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/thebluefowl/burrow/internal/index"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all uploaded files",
	Long:  `Lists all files you have uploaded to Backblaze B2, showing their object IDs, original file names, and upload dates.`,
	RunE:  runList,
}

func runList(cmd *cobra.Command, args []string) error {
	// Get password to decrypt index
	password, err := askMasterPassword()
	if err != nil {
		return fmt.Errorf("failed to get master password: %w", err)
	}

	// Load index from local encrypted file (no API calls!)
	idx, err := index.Load(password)
	if err != nil {
		return fmt.Errorf("failed to load index: %w", err)
	}

	if len(idx.Entries) == 0 {
		color.Yellow("No files found. Upload a file first using 'burrow upload'.")
		return nil
	}

	// Display the list
	printList(idx.Entries)
	return nil
}

func printList(entries []index.Entry) {
	color.New(color.BgWhite, color.FgBlack).Print(" Your Backups ")
	fmt.Println()
	fmt.Println()

	// Table header
	headerStyle := color.New(color.Bold, color.FgCyan)
	headerStyle.Printf("%-27s %-40s %-20s\n", "OBJECT ID", "FILE NAME", "UPLOADED")
	headerStyle.Printf("%s\n", strings.Repeat("-", 87))

	// Table rows
	for _, entry := range entries {
		// Format date
		dateStr := entry.CreatedAt.Format("2006-01-02 15:04:05")
		if entry.CreatedAt.IsZero() {
			dateStr = "Unknown"
		}

		// Truncate long file names
		fileName := entry.FileName
		if len(fileName) > 38 {
			fileName = fileName[:35] + "..."
		}

		fmt.Printf("%-27s %-40s %-20s\n", entry.ObjectID, fileName, dateStr)
	}

	fmt.Println()
	color.Green("✓ Found %d file(s)\n", len(entries))
	fmt.Println("To download a file, use: burrow download <object-id> <destination>")
}
