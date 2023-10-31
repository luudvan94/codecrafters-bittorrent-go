package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	bencode "github.com/jackpal/bencode-go" // Available if you need it!
)

// Example:
// - 5:hello -> hello
// - 10:hello12345 -> hello12345
type Torrent struct {
	Announce string `json:"announce"`
	Info     TorrentInfo `json:"info"`
}

type TorrentInfo struct {
	Length	int		`json:"length"`
	Name	string	`json:"name"`
	PieceLength	int	`json:"piece length"`
	Pieces 	string	`json:"pieces"`
}

type (
	List []interface{}
	Dict map[string]interface{}
)

func bencodeDict(dict Dict) []byte {
	keys := make([]string, 0, len(dict))
	for key := range dict {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteString("d")

	for _, key := range keys {
		value := dict[key]
		buf.WriteString(bencodeString(key))
		buf.Write(bencodeObject(value))
	}

	buf.WriteString("e")

	return buf.Bytes()
}

func bencodeString(s string) string {
	return fmt.Sprintf("%d:%s", len(s), s)
}

func bencodeObject(value interface{}) []byte {
	switch v := value.(type) {
	case string:
		return []byte(bencodeString(v))
	case int:
		return []byte(fmt.Sprintf("i%de", v))
	case List:
		return bencodeList(v)
	case Dict:
		return bencodeDict(v)
	default:
		return nil
	}
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

func bencodeList(lst []interface{}) []byte {
	var buf bytes.Buffer
	buf.WriteString("l")

	for _, item := range lst {
		buf.Write(bencodeObject(item))
	}

	buf.WriteString("e")
	return buf.Bytes()
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
		torrent := Torrent{}
		
		err = json.Unmarshal([]byte(jsonOutput), &torrent)
		if err != nil {
			fmt.Println("Error unmarshaling JSON:", err)
			return
		}

		decodedDict, ok := decoded.(map[string]interface{})
		if !ok {
			fmt.Println("Error casting decoded to Dict")
			return
		}

		infoDict, ok := decodedDict["info"]
		if !ok {
			fmt.Println("info is not found in decodedDict", err)
			return
		}

		encodedInfo := bencodeObject(infoDict)
		hash := sha1.Sum(encodedInfo)
		// Print the extracted information
		fmt.Printf("Tracker URL: %s\n", torrent.Announce)
		fmt.Printf("Length: %d\n", torrent.Info.Length)
		fmt.Printf("Info Hash: %x\n", hash)
	} else {
		fmt.Println("Unknown command: " + command)
		os.Exit(1)
	}
}
