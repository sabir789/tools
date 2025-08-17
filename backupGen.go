package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// defaultExtensions contains a common list of file extensions that will be appended
// to your keywords unless custom extensions are exclusively provided.
var defaultExtensions = []string{
	".sh", ".zip", ".json", ".yml", ".yaml", ".bak", ".old", ".txt", ".log",
	".conf", ".cfg", ".env", ".sql", ".db", ".git", ".tar.gz", ".tar", ".tgz",
	".rar", ".7z", ".csv", ".xml", ".html", ".php", ".asp", ".jsp", ".py",
	".js", ".css", ".md", ".doc", ".docx", ".pdf", ".png", ".jpg", ".jpeg", ".gif",
}

func main() {
	var (
		keywordInput string // Stores a single keyword provided via -k flag
		inputFile    string // Stores the path to an input file via -f flag
		customExts   string // Stores a comma-separated list of custom extensions via -e flag
	)

	// Define command-line flags for user input
	flag.StringVar(&keywordInput, "k", "", "Specify a single keyword to generate extensions for. Example: -k config")
	flag.StringVar(&inputFile, "f", "", "Provide an input file containing keywords, one per line. Example: -f keywords.txt")
	flag.StringVar(&customExts, "e", "", "Supply a comma-separated list of custom extensions to use instead of (or in addition to) defaults. Example: -e .exe,.dll")
	flag.Parse() // Parse the command-line arguments

	// Prepare the list of extensions to use
	allExtensions := defaultExtensions
	if customExts != "" {
		userExtensions := []string{}
		parts := strings.Split(customExts, ",")
		for _, part := range parts {
			// Ensure custom extensions start with a dot
			if !strings.HasPrefix(part, ".") {
				part = "." + part
			}
			userExtensions = append(userExtensions, part)
		}
		// If custom extensions are provided, prioritize them. You can decide if you want
		// to *only* use custom extensions or append them to defaults.
		// For now, we'll append them to defaults.
		allExtensions = append(allExtensions, userExtensions...)
	}

	// Determine the input source for keywords: single keyword, file, or pipeline (stdin)
	var inputReader io.Reader // An interface that can read data

	if keywordInput != "" {
		// If -k flag is used, read from the string directly
		inputReader = strings.NewReader(keywordInput + "\n")
	} else if inputFile != "" {
		// If -f flag is used, open the specified file
		file, err := os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening input file %s: %v\n", inputFile, err)
			os.Exit(1)
		}
		defer file.Close() // Ensure the file is closed after function execution
		inputReader = file
	} else {
		// If neither -k nor -f is used, assume input comes from stdin (pipeline)
		stat, _ := os.Stdin.Stat() // Get information about stdin
		// Check if stdin is an interactive terminal and no data is buffered/piped
		if (stat.Mode()&os.ModeCharDevice) != 0 && stat.Size() == 0 {
			fmt.Fprintf(os.Stderr, "Error: No input provided. Use -k for a single keyword, -f for an input file, or pipe input (e.g., echo 'keyword' | %s).\n", os.Args[0])
			os.Exit(1)
		}
		inputReader = os.Stdin // Set input source to standard input
	}

	// Process each line (keyword) from the determined input source
	scanner := bufio.NewScanner(inputReader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text()) // Read and trim whitespace from the line
		if line == "" {
			continue // Skip empty lines
		}

		// Extract base keywords from the input line (e.g., "sub" and "domain" from "sub.domain.com")
		keywords := extractKeywords(line)
		for _, kw := range keywords {
			if kw == "" {
				continue // Skip any empty extracted keywords
			}
			// For each extracted keyword, append all defined extensions and print to stdout
			for _, ext := range allExtensions {
				fmt.Printf("%s%s\n", kw, ext)
			}
		}
	}

	// Check for any errors during scanning
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}
}

// extractKeywords intelligently extracts relevant base keywords from an input string.
// It handles domain names (e.g., "sub.domain.com" -> "sub", "domain") and file paths
// (e.g., "app/config" -> "config", "app").
func extractKeywords(input string) []string {
	var extracted []string
	seen := make(map[string]struct{}) // Use a map to ensure uniqueness of extracted keywords

	// Clean up common URL/domain prefixes for better keyword extraction
	cleanInput := strings.TrimPrefix(input, "http://")
	cleanInput = strings.TrimPrefix(cleanInput, "https://")
	cleanInput = strings.TrimPrefix(cleanInput, "www.")

	// Case 1: The input looks like a file path (contains '/')
	if strings.Contains(cleanInput, "/") {
		// Split the path into its components
		parts := strings.Split(cleanInput, "/")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" && part != "." && part != ".." { // Exclude empty parts and directory navigation
				// If a part has a file extension (e.g., "script.sh"), also extract the base name ("script")
				if strings.Contains(part, ".") {
					ext := filepath.Ext(part)
					base := strings.TrimSuffix(part, ext)
					if base != "" {
						if _, ok := seen[base]; !ok {
							extracted = append(extracted, base)
							seen[base] = struct{}{}
						}
					}
				}
				// Add the part itself (e.g., "config", "app")
				if _, ok := seen[part]; !ok {
					extracted = append(extracted, part)
					seen[part] = struct{}{}
				}
			}
		}
	} else if strings.Contains(cleanInput, ".") {
		// Case 2: The input looks like a domain name (contains '.' but not '/')
		// This heuristic extracts subdomains and the main domain part, excluding the TLD.
		parts := strings.Split(cleanInput, ".")
		if len(parts) >= 2 {
			// Add the main domain part (e.g., "domain" from "sub.domain.com" or "domain.com")
			domainPart := parts[len(parts)-2]
			if _, ok := seen[domainPart]; !ok {
				extracted = append(extracted, domainPart)
				seen[domainPart] = struct{}{}
			}

			// Add subdomains (e.g., "sub" from "sub.domain.com")
			for i := 0; i < len(parts)-2; i++ { // Iterate up to the part before the main domain
				subdomainPart := parts[i]
				if _, ok := seen[subdomainPart]; !ok {
					extracted = append(extracted, subdomainPart)
					seen[subdomainPart] = struct{}{}
				}
			}
		} else if cleanInput != "" { // Handle cases like "example" or "single.word" if split didn't yield >=2 parts
			if _, ok := seen[cleanInput]; !ok {
				extracted = append(extracted, cleanInput)
				seen[cleanInput] = struct{}{}
			}
		}
	} else {
		// Case 3: A simple single keyword (no '/' or '.')
		if cleanInput != "" {
			if _, ok := seen[cleanInput]; !ok {
				extracted = append(extracted, cleanInput)
				seen[cleanInput] = struct{}{}
			}
		}
	}

	return extracted // The slice 'extracted' already contains unique elements
}
