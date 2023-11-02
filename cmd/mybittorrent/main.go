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

type IPAddress struct {
	IP			string
	Port		int
}

type HandShakeResponse struct {
	PeerID		[]byte
}

func (r GetPeersResponse) PeersAddr() []IPAddress {
	var peerList []IPAddress
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
        peerStr := IPAddress{IP: ip.String(), Port: port}
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

func CalculateInfoHash(info TorrentInfo) ([20]byte, error) {
	var s = sha1.New()
	err := bencode.Marshal(s, info)
	if err != nil {
		return [20]byte{}, err
	}

	hashBytes := s.Sum(nil)

	var hash [20]byte
	copy(hash[:], hashBytes)

	return hash, nil
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
	q.Add("info_hash", hex.EncodeToString(infoHash[:]))
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


func ParseHandshakeResponse(conn net.Conn) (HandShakeResponse, error) {
	// Read the handshake response from the remote peer
	handshakeResponse := make([]byte, 68) // Assuming a fixed-size response
	_, err := conn.Read(handshakeResponse)
	if err != nil {
		return HandShakeResponse{}, err
	}

	// Extract information from the handshake response
	// pstrlen := handshakeResponse[0]           // Length of pstr
	// pstr := string(handshakeResponse[1:20])   // Protocol identifier (e.g., "BitTorrent protocol")
	// reserved := handshakeResponse[20:28]     // Reserved bytes
	// infoHash := handshakeResponse[28:48]     // Info hash (20 bytes)
	peerID := handshakeResponse[48:68]       // Peer ID (20 bytes)

	// Convert pstrlen to an integer to determine the length of pstr
	// pstrlenInt := int(pstrlen)

	response := HandShakeResponse{}
	// fmt.Printf("pstrlen: %d\n", pstrlenInt)
	// fmt.Printf("pstr: %s\n", pstr)
	// fmt.Printf("reserved: %v\n", reserved)
	// fmt.Printf("infoHash: %v\n", infoHash)
	response.PeerID = peerID

	// Additional processing based on the extracted information can be done here

	return response, nil
}

func SendHandShake(desAddr string, infoHash [20]byte, peerID string) (HandShakeResponse, error) {
	conn, err := net.Dial("tcp", desAddr)
	if err != nil {
		return HandShakeResponse{}, err
	}
	defer conn.Close()

	protocolString := "BitTorrent protocol"
	var handshake bytes.Buffer
	handshake.WriteByte(byte(len(protocolString)))
	handshake.WriteString(protocolString)

	reservedBytes := make([]byte, 8)
	handshake.Write(reservedBytes)
	
	handshake.Write(infoHash[:])

	handshake.Write([]byte(peerID))

	_, err = conn.Write(handshake.Bytes())
	if err != nil {
		return HandShakeResponse{}, err
	}


	res, err := ParseHandshakeResponse(conn)
	if err != nil {
		return HandShakeResponse{}, err
	}

	return res, nil
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
			fmt.Printf("%s:%d\n", addr.IP, addr.Port)
		}
		return

	case "handshake":
		torrentFileName := os.Args[2]
		t, err := ParseTorrentFile(torrentFileName)
		if err != nil {
			fmt.Println(err)
			return
		}

		peerAddr := os.Args[3]

		infoHash, err := CalculateInfoHash(t.Info)
		if err != nil {
			fmt.Println(err)
			return
		}

		res, err := SendHandShake(peerAddr, infoHash, "00112233445566778899")
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Printf("Peer ID: %x\n", res.PeerID)
		return

	default:
		fmt.Println("Unknown command: " + command)
	}
}
