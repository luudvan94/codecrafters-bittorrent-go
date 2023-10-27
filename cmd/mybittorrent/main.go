package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	bencode "github.com/jackpal/bencode-go" // Available if you need it!
)

// Example:
// - 5:hello -> hello
// - 10:hello12345 -> hello12345

type TorrentInfo struct {
	Announce string `json:"announce"`
	Info     struct {
		Length     int    `json:"length"`
	} `json:"info"`
}

// ReadFileContent reads and returns the content of a file.
func ReadFileContent(filePath string) (string, error) {
	// Open the file for reading
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Read the file content
	content, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	// Convert the content to a string
	fileContent := string(content)

	return fileContent, nil
}

func main() {

	command := os.Args[1]

	if command == "decode" {
		bencodedValue := os.Args[2]
		
		decoded, err := bencode.Decode(strings.NewReader((bencodedValue)))
		if err != nil {
			fmt.Println(err)
			return
		}
		
		jsonOutput, _ := json.Marshal(decoded)
		fmt.Println(string(jsonOutput))
	} else if command == "info" {
		filePath := os.Args[2]
		content, err := ReadFileContent(filePath)
		
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		decoded, err := bencode.Decode(strings.NewReader((content)))
		if err != nil {
			fmt.Println(err)
			return
		}
		
		jsonOutput, _ := json.Marshal(decoded)
		var torrentInfo TorrentInfo
		
		err = json.Unmarshal([]byte(jsonOutput), &torrentInfo)
		if err != nil {
			fmt.Println("Error unmarshaling JSON:", err)
			return
		}

		// Print the extracted information
		fmt.Printf("Tracker URL: %s\n", torrentInfo.Announce)
		fmt.Printf("Length: %d\n", torrentInfo.Info.Length)
	} else {
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
