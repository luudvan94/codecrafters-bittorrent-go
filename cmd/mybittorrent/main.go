package main

import (
	// Uncomment this line to pass the first stage
	// "encoding/json"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
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
type (
	List []interface{}
	Dict map[string]interface{}
)

func decodeBencode(bencodedStr string) (interface{}, int, error) {
	switch bencodedStr[0] {
	case 'l':
		return decodeBencodeList(bencodedStr)
	case 'i':
		return decodeBencodeInt(bencodedStr)
	case 'd':
		return decodeBencodeDict(bencodedStr)
	default:
		return decodeBencodeString(bencodedStr)
	}
}
func decodeBencodeString(bencodedString string) (string, int, error) {
	indexColon := strings.Index(bencodedString, ":")
	length, err := strconv.Atoi(bencodedString[:indexColon])
	if err != nil {
		return "", 0, fmt.Errorf("strconv.Atoi: parsing \"%s\": invalid syntax", bencodedString[:indexColon])
	}
	content := bencodedString[indexColon+1 : indexColon+1+length]
	return content, indexColon + 1 + length, nil
}
func decodeBencodeInt(bencodedString string) (int, int, error) {
	firstEnd := strings.Index(bencodedString, "e")
	integer, err := strconv.Atoi(bencodedString[1:firstEnd])
	if err != nil {
		return 0, 0, fmt.Errorf("strconv.Atoi: parsing \"%s\": invalid syntax", bencodedString[1:firstEnd])
	}
	return integer, firstEnd + 1, nil
}

func decodeBencodeList(bencodedString string) (List, int, error) {
	decodedList := List{}
	i := 1
	for bencodedString[i] != 'e' {
		decoded, indexEnd, err := decodeBencode(bencodedString[i:])
		if err != nil {
			return nil, 0, fmt.Errorf("decodeBencode: parsing \"%s\": invalid syntax", bencodedString[i:])
		}
		decodedList = append(decodedList, decoded)
		i += indexEnd
	}
	return decodedList, i, nil
}

func decodeBencodeDict(bencodedString string) (Dict, int, error) {
	decodedDict := make(Dict)
	i := 1
	var currKey interface{} = nil
	for bencodedString[i] != 'e' {
		decoded, indexEnd, err := decodeBencode(bencodedString[i:])
		if err != nil {
			return nil, 0, fmt.Errorf("decodeBencode: parsing \"%s\": invalid syntax", bencodedString[i:])
		}
		if currKey == nil {
			currKey = decoded
			decodedDict[fmt.Sprintf("%v", currKey)] = nil
		} else {
			decodedDict[fmt.Sprintf("%v", currKey)] = decoded
			currKey = nil
		}
		i += indexEnd
	}
	return decodedDict, i, nil
}

func encodeBencode(bencodedData interface{}) (string, error) {
	switch data := bencodedData.(type) {
	case string:
		return fmt.Sprintf("%d:%s", len(data), data), nil
	case int:
		return fmt.Sprintf("i%de", data), nil
	case List:
		bencoded := ""
		for _, elem := range data {
			encoded, err := encodeBencode(elem)
			if err != nil {
				return "", err
			}
			bencoded += encoded
		}
		return fmt.Sprintf("l%se", bencoded), nil
	case Dict:
		bencoded := ""
		keys := []string{}
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value, ok := data[key]
			if !ok {
				return "", fmt.Errorf("value for key %s does not exist", key)
			}
			encodedKey, err := encodeBencode(key)
			if err != nil {
				return "", err
			}
			encodedValue, err := encodeBencode(value)
			if err != nil {
				return "", err
			}
			bencoded += fmt.Sprintf("%s%s", encodedKey, encodedValue)
		}
		return fmt.Sprintf("d%se", bencoded), nil
	default:
		return "", errors.New("wrong bencoded data type")
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
		bencodedValue := string(contentBytes)
		decoded, _, err := decodeBencode(bencodedValue)
		if err != nil {
			fmt.Println(err)
			return
		}
		jsonOutput, _ := json.Marshal(decoded)
		t := Torrent{}
		json.Unmarshal(jsonOutput, &t)
		decodedDict, ok := decoded.(Dict)
		if !ok {
			fmt.Println("decoded is not a dict")
			return
		}
		infoDict, ok := decodedDict["info"]
		if !ok {
			fmt.Println("info dict is not found in decoded dict")
			return
		}
		encodedInfo, err := encodeBencode(infoDict)
		if err != nil {
			fmt.Printf("encodeBencode failed: %v \n", err)
			return
		}
		sum := sha1.Sum([]byte(encodedInfo))
		fmt.Println("Tracker URL:", t.Announce)
		fmt.Println("Length:", t.Info.Length)
		fmt.Printf("Info Hash: %s", hex.EncodeToString(sum[:]))
	default:
		fmt.Println("Unknown command: " + command)
	}
}
