package main

import (
	// Uncomment this line to pass the first stage
	// "encoding/json"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
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
	Announce string      "announce"
	Info     TorrentInfo "info"
}
type TorrentInfo struct {
	Length      int    "length"
	Name        string "name"
	PieceLength int    "piece length"
	Pieces      string "pieces"
}

func splitBytes(input []byte, chunkSize int) [][]byte {
    if chunkSize <= 0 {
        return nil
    }

    var result [][]byte
    for i := 0; i < len(input); i += chunkSize {
        end := i + chunkSize
        if end > len(input) {
            end = len(input)
        }
        result = append(result, input[i:end])
    }
    return result
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

		bytesChunk := splitBytes([]byte(t.Info.Pieces), 20)

		fmt.Println("Tracker URL:", t.Announce)
		fmt.Println("Length:", t.Info.Length)
		fmt.Printf("Info Hash: %x\n", sum)
		fmt.Println("Piece Length:", t.Info.PieceLength)
		fmt.Println("Piece Hashes:")
		for _, chunk := range bytesChunk {
			fmt.Println(string(hex.EncodeToString(chunk)))
		}

	default:
		fmt.Println("Unknown command: " + command)
	}
}
