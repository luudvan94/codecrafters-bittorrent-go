package main

import (
	// Uncomment this line to pass the first stage
	// "encoding/json"
	"bytes"
	"crypto/sha1"
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
type Torrent struct {
	Announce string      `json:"announce"`
	Info     TorrentInfo `json:"info"`
}
type TorrentInfo struct {
	Length      int    `json:"length"`
	Name        string `json:"name"`
	PieceLength int    `json:"piece length"`
	Pieces      string `json:"pieces"`
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

	switch command {
	case "decode":
		bencodedValue := os.Args[2]
		decoded, err := bencode.Decode(strings.NewReader(bencodedValue))
		if err != nil {
			fmt.Println(err)
			return
		}
		jsonOutput, _ := json.Marshal(decoded)
		fmt.Println(string(jsonOutput))
	case "info":
		torrentFilePath := os.Args[2]
		contentBytes, err := os.ReadFile(torrentFilePath)
		if err != nil {
			fmt.Println(err)
		}
		t := Torrent{}
		bencodedValue := string(contentBytes)
		bencode.Unmarshal(strings.NewReader(bencodedValue), &t)
		decoded, err := bencode.Decode(strings.NewReader(bencodedValue))
		if err != nil {
			fmt.Println(err)
			return
		}

		decodedDict, ok := decoded.(map[string]interface{})
		if (!ok) {
			fmt.Println("error parsing decoded")
			return
		}

		var buf bytes.Buffer
		err = bencode.Marshal(&buf, decodedDict["info"])
		if err != nil {
			fmt.Println(err)
			return
		}

		sum := sha1.Sum(buf.Bytes())
		fmt.Println("Tracker URL:", t.Announce)
		fmt.Println("Length:", t.Info.Length)
		fmt.Printf("Info Hash: %x\n", sum)
	default:
		fmt.Println("Unknown command: " + command)
	}
}
