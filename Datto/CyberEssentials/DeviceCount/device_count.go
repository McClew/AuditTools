package main

import (
	// Standard dependencies
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"

	// External dependencies
	"github.com/spf13/cobra"
)

// Models
type csvData struct {
	Hostname              string
	DeviceType            string
	OSVersion             string
	WindowsDisplayVersion string
	Manufacturer          string
}

type countData struct {
	OSVersion             string
	WindowsDisplayVersion string
	Manufacturer          string
	Count                 int
}

// Define variables
var csvFile string

// Functions
func main() {
	// Execute the root command & catch any errors
	if err := rootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCommand() *cobra.Command {
	// Define the root command
	var command = &cobra.Command{
		Use:   "Asset-Formater",
		Short: "Formats Datto RMM export to required format for CyberEssentials",
		Long:  "Formats Datto RMM export to required format for CyberEssentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			return execution()
		},
	}

	// Disable the default help command
	// Help is accessed via the -h or --help flags
	command.SetHelpCommand(&cobra.Command{
		Use:    "no-help",
		Hidden: true,
	})

	// Define persistent flags
	command.PersistentFlags().StringVarP(&csvFile, "file", "f", "", "Path to the CSV file to process")

	return command
}

func execution() error {
	csvRows := parseCsv(csvFile)

	// Use a map to group rows with the same attributes
	counts := make(map[string]*countData)

	for _, row := range csvRows {
		// Create a unique key for this combination
		key := fmt.Sprintf("%s|%s|%s", row.OSVersion, row.WindowsDisplayVersion, row.Manufacturer)

		if value, exists := counts[key]; exists {
			// If exists - increment the count
			value.Count++
		} else {
			counts[key] = &countData{
				OSVersion:             row.OSVersion,
				WindowsDisplayVersion: row.WindowsDisplayVersion,
				Manufacturer:          row.Manufacturer,
				Count:                 1,
			}
		}
	}

	// Output the results
	fmt.Println("\n--- Formatted CyberEssentials Report ---")
	for _, data := range counts {
		fmt.Printf("%s, %s, %s - [x%d]\n",
			data.OSVersion,
			data.WindowsDisplayVersion,
			data.Manufacturer,
			data.Count)
	}

	return nil
}

func parseCsv(csvFile string) []csvData {
	// Open the CSV file
	file, err := os.Open(csvFile)

	// Error handling for file opening
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open CSV file: %v\n", err)
		return nil
	}

	defer file.Close()

	// Create a new CSV reader
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // Allow variable number of fields

	// Read the header row
	headers, err := reader.Read()

	// Error handling for reading headers
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read CSV headers: %v\n", err)
		return nil
	}

	// Map header names to their column indices for easy access
	headerMap := make(map[string]int)
	for index, header := range headers {
		headerMap[strings.ToLower(strings.TrimSpace(header))] = index
	}

	var csvDataMap []csvData

	for {
		// Read each record from the CSV
		record, err := reader.Read()

		// Error handing for end of file
		if err == io.EOF {
			break // End of file reached
		}

		var csvRowMap csvData

		for columnName, index := range headerMap {
			if index < len(record) {
				value := record[index]

				switch columnName {
				case "hostname":
					csvRowMap.Hostname = value
				case "type":
					csvRowMap.DeviceType = value
				case "os":
					csvRowMap.OSVersion = value
				case "windows display version":
					csvRowMap.WindowsDisplayVersion = value
				case "manufacturer":
					csvRowMap.Manufacturer = value
				}
			}
		}

		csvDataMap = append(csvDataMap, csvRowMap)
	}

	return csvDataMap
}
