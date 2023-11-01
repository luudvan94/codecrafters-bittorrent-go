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
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	bencode "github.com/jackpal/bencode-go"
	// Available if you need it!
)

// Example:
// - 5:hello -> hello
// - 10:hello12345 -> hello12345
type Torrent struct {
	Announce string      `bencode:"announce"`
	Info     TorrentInfo `bencode:"info"`
}
type TorrentInfo struct {
	Length      int    `bencode:"length"`
	Name        string `bencode:"name"`
	PieceLength int    `bencode:"piece length"`
	Pieces      string `bencode:"pieces"`
}

type GetPeersResponse struct {
	Interval 	int 	`bencode:"interval"`
	Peers 		string	`bencode:"peers"`
}

func (r GetPeersResponse) PeersAddr() []string {
	var peerList []string
	peerInfo := r.Peers
    // Check that the peerInfo string has a length that is a multiple of 6 (each peer entry is 6 bytes)
    if len(peerInfo)%6 != 0 {
        fmt.Println("Invalid peer information length")
        return peerList
    }

    // Split the peerInfo string into 6-byte segments
    for i := 0; i < len(peerInfo); i += 6 {
        ipBytes := peerInfo[i : i+4]
        portBytes := peerInfo[i+4 : i+6]

        // Convert the 4-byte IP address and 2-byte port number to their respective values
        ip := net.IP(ipBytes)
        port := int(portBytes[0])<<8 + int(portBytes[1])

        // Create the formatted peer string
        peerStr := fmt.Sprintf("%s:%d", ip.String(), port)
        peerList = append(peerList, peerStr)
    }

    return peerList
}

func SplitBytes(input []byte, chunkSize int) [][]byte {
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

func ParseTorrentFile(fileName string) (Torrent, error) {
	contentBytes, err := os.ReadFile(fileName)
	if err != nil {
		return Torrent{}, err
	}

	t := Torrent{}
	err = bencode.Unmarshal(strings.NewReader(string(contentBytes)), &t)
	if err != nil {
		return Torrent{}, err
	}

	return t, nil
}

func CalculateInfoHash(info TorrentInfo) ([]byte, error) {
	var s = sha1.New()
	err := bencode.Marshal(s, info)
	if err != nil {
		return []byte{}, err
	}

	return s.Sum(nil), nil
}

func GetPeers(torrent Torrent) (GetPeersResponse, error) {
	baseUrl, err := url.Parse(torrent.Announce)
	if err != nil {
		fmt.Println("Error parsing URL:", err)
		return GetPeersResponse{}, err
	}

	infoHash, err := CalculateInfoHash(torrent.Info)
	if err != nil {
		fmt.Println("Error calculating info hash:", err)
		return GetPeersResponse{}, err
	}

	q := baseUrl.Query()
	q.Add("info_hash", string(infoHash))
	q.Add("peer_id", "11112233445566778899")
	q.Add("port", "6881")
	q.Add("uploaded", "0")
	q.Add("downloaded", "0")
	q.Add("left", fmt.Sprintf("%d", torrent.Info.Length))
	q.Add("compact", "1")
	baseUrl.RawQuery = q.Encode()

	resp, err := http.Get(baseUrl.String())
	if err != nil {
		fmt.Println("Error sending request:", err)
		return GetPeersResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Request failed with status: %s\n", resp.Status)
		return GetPeersResponse{}, nil
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return GetPeersResponse{}, err
	}

	var getPeersResponse GetPeersResponse
	err = bencode.Unmarshal(bytes.NewReader(content), &getPeersResponse)
	if err != nil {
		fmt.Println("Error parsing response:", err)
		return GetPeersResponse{}, err
	}
	
	return getPeersResponse, nil
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
		torrentFileName := os.Args[2]
		t, err := ParseTorrentFile(torrentFileName)
		if err != nil {
			fmt.Println(err)
			return
		}

		hash, err := CalculateInfoHash(t.Info)
		if err != nil {
			fmt.Println(err)
			return
		}

		bytesChunk := SplitBytes([]byte(t.Info.Pieces), 20)

		fmt.Println("Tracker URL:", t.Announce)
		fmt.Println("Length:", t.Info.Length)
		fmt.Printf("Info Hash: %x\n", hash)
		fmt.Println("Piece Length:", t.Info.PieceLength)
		fmt.Println("Piece Hashes:")
		for _, chunk := range bytesChunk {
			fmt.Println(string(hex.EncodeToString(chunk)))
		}
	case "peers":
		torrentFileName := os.Args[2]
		t, err := ParseTorrentFile(torrentFileName)
		if err != nil {
			fmt.Println(err)
			return
		}

		peers, err := GetPeers(t) 
		if err != nil {
			fmt.Println(err)
			return
		}
		
		peerAddrs := peers.PeersAddr()
		
		for _, addr := range peerAddrs {
			fmt.Println(addr)
		}
		return

	default:
		fmt.Println("Unknown command: " + command)
	}
}
