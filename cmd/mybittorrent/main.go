package main

import (
	// Uncomment this line to pass the first stage
	// "encoding/json"

	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
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

type Peer struct {
	IP			string
	Port		int
}

type HandShakeResponse struct {
	PeerID		[]byte
}

type TorrentClient struct {
	peerID  			string
	connMap 			map[string]net.Conn
	maxConcurrency		int
}

type Piece struct {
	Data 		[]byte
	PieceIndex	int
}

type Block struct {
	Data		[]byte
	Index		uint32
	Length		int
	PieceIndex	int
}

// NewClient is a constructor function for Client
func NewClient(peerID string) *TorrentClient {
	return &TorrentClient{
		peerID:  peerID,
		connMap: make(map[string]net.Conn),
		maxConcurrency: 1,
	}
}

func (r GetPeersResponse) ParsePeers() []Peer {
	var peerList []Peer
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
        peerStr := Peer{IP: ip.String(), Port: port}
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

func (torrent Torrent)CalculateInfoHash() ([]byte, error) {
	var s = sha1.New()
	err := bencode.Marshal(s, torrent.Info)
	if err != nil {
		return []byte{}, err
	}

	hashBytes := s.Sum(nil)

	return hashBytes, nil
}

func (torrent Torrent)GetPeers() ([]Peer, error) {
	baseUrl, err := url.Parse(torrent.Announce)
	if err != nil {
		fmt.Println("Error parsing URL:", err)
		return []Peer{}, err
	}

	infoHash, err := torrent.CalculateInfoHash()
	if err != nil {
		fmt.Println("Error calculating info hash:", err)
		return []Peer{}, err
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
		return []Peer{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return []Peer{}, fmt.Errorf("Request failed with status: %s\n", resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return []Peer{}, err
	}

	var getPeersResponse GetPeersResponse
	err = bencode.Unmarshal(bytes.NewReader(content), &getPeersResponse)
	if err != nil {
		fmt.Println("Error parsing response:", err)
		return []Peer{}, err
	}
	
	return getPeersResponse.ParsePeers(), nil
}


func (cli TorrentClient) parseHandshakeResponse(handshakeResponse []byte) (HandShakeResponse) {
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

	return response
}

func (cli TorrentClient) openConnection(protocol string, addr string) (net.Conn, error) {
	// if conn, exists := cli.connMap[addr]; exists {
	// 	return conn, nil
	// }

	conn, err := net.Dial(protocol, addr)
	if err != nil {
		return nil, err
	}
	// cli.connMap[addr] = conn

	return conn, nil
}

func (cli TorrentClient) closeConnection(conn net.Conn) {
	conn.Close()
}

func (cli TorrentClient) handshakeMessage(infoHash []byte) []byte {
	protocolString := "BitTorrent protocol"
	var handshake bytes.Buffer
	handshake.WriteByte(byte(len(protocolString)))
	handshake.WriteString(protocolString)

	reservedBytes := make([]byte, 8)
	handshake.Write(reservedBytes)
	
	handshake.Write(infoHash[:])

	handshake.Write([]byte(cli.peerID))

	return handshake.Bytes()
}

func (cli TorrentClient) sendMessage(msg []byte, conn net.Conn) error {
	_, err := conn.Write(msg)
	if err != nil {
		return err
	}

	return nil
}

func (cli TorrentClient) readResponse(conn net.Conn, result []byte) ([]byte, error) {
	_, err := conn.Read(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (cli TorrentClient) readMessage(conn net.Conn) (byte, []byte, error) {
	lengthBytes := make([]byte, 4)
	if _, err := cli.readResponse(conn, lengthBytes); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(lengthBytes)
	messageType := make([]byte, 1)
	if _, err := cli.readResponse(conn, messageType); err != nil {
		return 0, nil, err
	}
	length--
	// fmt.Printf("readMessageLength: %d \n", int(length))
	message := make([]byte, length)
	if _, err := io.ReadAtLeast(conn, message, int(length)); err != nil {
		return 0, nil, err
	}

	return messageType[0], message, nil
}

func (cli TorrentClient) HandSHake(desAddr string, infoHash []byte) (HandShakeResponse, error) {
	conn, err := cli.openConnection("tcp", desAddr)
	if err != nil {
		return HandShakeResponse{}, err
	}
	defer cli.closeConnection(conn)

	handshakeMsg := cli.handshakeMessage(infoHash)

	err = cli.sendMessage(handshakeMsg, conn)
	if err != nil {
		return HandShakeResponse{}, err
	}

	rawRes, err := cli.readResponse(conn, make([]byte, 68))
	if err != nil {
		return HandShakeResponse{}, err
	}

	res := cli.parseHandshakeResponse(rawRes)
	return res, nil
}

func (cli TorrentClient) createMessage(messageID byte, payload []byte) []byte {
	messageLength := 1 + len(payload) // Message ID (1 byte) + Payload Length
	message := make([]byte, 4+messageLength) // Length (4 bytes) + Message ID + Payload

	// Set the length (excluding the 4 length bytes)
	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf, uint32(messageLength))

	copy(message[:4], sizeBuf)
	// Set the message ID
	copy(message[4:5], []byte{messageID})

	// Set the payload
	copy(message[5:], payload)

	return message
}

func (cli TorrentClient) createBlockMessages(pieceIndex int, pieceLength int) ([][]byte) {
	
	blockSize := 16 * 1024 // 16 KiB
	// fmt.Printf("%d %d\n", pieceLength, pieceLength / blockSize)
	// numBlocks := (pieceLength + blockSize - 1) / blockSize
	requestMessages := make([][]byte, 0)
	// fmt.Printf("piece-index: %d piece-length: %d \n", pieceIndex, pieceLength)
	for i := 0; i < pieceLength; i += blockSize {
		length := blockSize
		if i+blockSize > pieceLength {
			length = pieceLength - i
		}
		begin := i
		// Create the request message
		message := make([]byte, 12) // 4 bytes for length, 1 byte for message ID, 4 bytes for index, 4 bytes for begin, 4 bytes for length                                            // Message ID for "request"
		binary.BigEndian.PutUint32(message[0:4], uint32(pieceIndex)) // Piece index
		binary.BigEndian.PutUint32(message[4:8], uint32(begin))    // Byte offset within the piece
		binary.BigEndian.PutUint32(message[8:12], uint32(length))   // Length of the block

		requestMessages = append(requestMessages, cli.createMessage(byte(6), message))
	}
	return requestMessages
}

func (cli TorrentClient) calculatePieceHash(pieceData []byte) string {
	// Create a new SHA-1 hash object
    sha1Hash := sha1.New()

    // Write the data to the hash object
    sha1Hash.Write(pieceData)

    // Get the 20-byte hash sum
    hashSum := sha1Hash.Sum(nil)

    // Convert the hash sum to a hex-encoded string
    hashString := hex.EncodeToString(hashSum)

    return hashString
}

func (client TorrentClient) ReadBlock(conn net.Conn) (uint32, uint32, []byte, error) {
	_, message, err := client.readMessage(conn)
	if err != nil {
		return 0, 0, nil, err
	}

	// fmt.Printf("message length: %d \n", len(message))
	pieceIndex := binary.BigEndian.Uint32(message[0:4])
	begin := binary.BigEndian.Uint32(message[4:8])
	block := message[8:]
	return pieceIndex, begin, block, nil
}

func (cli TorrentClient) DownloadBlock(conn net.Conn, pieceIndex int, blockMsg []byte) (Block, error) {
	// fmt.Printf("Download block (pieceIndex: %d)\n", pieceIndex)

	err := cli.sendMessage(blockMsg, conn)
	if err != nil {
		return Block{}, err
	}
	
	recievedPieceIndex, recievedBlockIndex, block, err := cli.ReadBlock(conn)
	if err != nil {
		return Block{}, err
	}
	if recievedPieceIndex != uint32(pieceIndex) {
		return Block{}, err
	}
	
	return Block{Data: block, PieceIndex: int(pieceIndex), Index: recievedBlockIndex}, nil
}

func (cli TorrentClient) DownloadPiece(desAddr string, infoHash []byte, info TorrentInfo, pieceIndex int) (Piece, error) {
	conn, err := cli.openConnection("tcp", desAddr)
	if err != nil {
		return Piece{}, err
	}
	defer cli.closeConnection(conn)

	handshakeMsg := cli.handshakeMessage(infoHash)
	err = cli.sendMessage(handshakeMsg, conn)
	if err != nil {
		return Piece{}, err
	}

	_, err = cli.readResponse(conn, make([]byte, 68))
	if err != nil {
		return Piece{}, err
	}

	_,_, err = cli.readMessage(conn)
	if err != nil {
		fmt.Println("Not found bitfield message type")
		return Piece{}, err
	}

	interestMsg := cli.createMessage(byte(2), []byte{})
	err = cli.sendMessage(interestMsg, conn)
	if err != nil {
		return Piece{}, err
	}

	_,_, err = cli.readMessage(conn)
	if err != nil {
		fmt.Println("Not found unchoke message type")
		return Piece{}, err
	}

	pieceLength := info.PieceLength
	length := info.Length
	if pieceIndex >= int(length/pieceLength) {
		pieceLength = length - (pieceLength * pieceIndex)
	}
	// fmt.Printf("length: %d piece-length: %d \n", info.Length,  pieceLength)
	data := make([]byte, pieceLength)
	blockMessages := cli.createBlockMessages(pieceIndex, pieceLength)
	for _, blockMsg := range blockMessages {
		block, err := cli.DownloadBlock(conn, pieceIndex, blockMsg)
		if err != nil {
			return Piece{}, err
		}
		
		copy(data[block.Index:], block.Data)
	}

	
	// fmt.Printf("piece length: %d\n", info.PieceLength)
	// fmt.Printf("data length: %d\n", len(data))
	// fmt.Printf("data: %x\n", data)
	// fmt.Println("here4")
	sha1Hash := sha1.New()

    // Write the input string to the hash object
    sha1Hash.Write(data)

    // Get the SHA-1 hash as a byte slice
    hashBytes := sha1Hash.Sum(nil)

    // Convert the byte slice to a hexadecimal string
    fmt.Printf("Hash: %x\n", hashBytes)
	
	return Piece{Data: data}, nil
}

func (cli TorrentClient) DownloadFile(torrent Torrent, peerAddr string) ([]byte, error) {
	infoHash, err := torrent.CalculateInfoHash()
	if err != nil {
		return []byte{}, err
	}

	data := make([]byte, torrent.Info.Length)
	bytesChunk := SplitBytes([]byte(torrent.Info.Pieces), 20)
	fmt.Printf("Length: %d pieceLength: %d \n", torrent.Info.Length, torrent.Info.PieceLength)
	for index,_ := range bytesChunk {
		startIndex := index * torrent.Info.PieceLength
		fmt.Printf("pieceIndex: %d byteIndex: %d\n", index, startIndex)
		if startIndex >= torrent.Info.Length {
			startIndex = torrent.Info.Length - (startIndex - 1) * torrent.Info.PieceLength
		}

		piece, err := cli.DownloadPiece(peerAddr, infoHash, torrent.Info, index)
		if err != nil {
			return []byte{}, err
		}
		
		copy(data[startIndex:], piece.Data)
	}

	return data, nil
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

		hash, err := t.CalculateInfoHash()
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

		peers, err := t.GetPeers()
		if err != nil {
			fmt.Println(err)
			return
		}
		
		for _, addr := range peers {
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

		infoHash, err := t.CalculateInfoHash()
		if err != nil {
			fmt.Println(err)
			return
		}

		cli := NewClient("00112233445566778899")
		res, err := cli.HandSHake(peerAddr, infoHash)
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Printf("Peer ID: %x\n", res.PeerID)
		return
	case "download_piece":
		outputFilePath := os.Args[3]
		torrentFileName := os.Args[4]
		pieceIndex, err := strconv.Atoi(os.Args[5])
		if err != nil {
			fmt.Println(err)
			return
		}

		t, err := ParseTorrentFile(torrentFileName)
		if err != nil {
			fmt.Println(err)
			return
		}

		peers, err := t.GetPeers()
		if err != nil {
			fmt.Println(err)
			return
		}
		
		peer := peers[0]
		peerAddr := fmt.Sprintf("%s:%d", peer.IP, peer.Port)
		// var infoHash []byte
		infoHash, err := t.CalculateInfoHash()
		if err != nil {
			fmt.Println(err)
			return
		}
		bytesChunk := SplitBytes([]byte(t.Info.Pieces), 20)
		fmt.Printf("Piecehash: %x\n", bytesChunk[pieceIndex])
		fmt.Printf("Pieces: %x\n", t.Info.Pieces)
		cli := NewClient("00112233445566778899")
		piece, err := cli.DownloadPiece(peerAddr, infoHash, t.Info, pieceIndex)
		if err != nil {
			fmt.Println(err)
			return
		}

		file, err := os.Create(outputFilePath)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		file.Write(piece.Data)

		fmt.Printf("Piece %d downloaded to %s\n", pieceIndex, outputFilePath)
		return
	case "download":
		outputFilePath := os.Args[3]
		torrentFileName := os.Args[4]

		torrent, err := ParseTorrentFile(torrentFileName)
		if err != nil {
			fmt.Println(err)
			return
		}

		peers, err := torrent.GetPeers()
		if err != nil {
			fmt.Println(err)
			return
		}
		
		peer := peers[0]
		peerAddr := fmt.Sprintf("%s:%d", peer.IP, peer.Port)

		cli := NewClient("00112233445566778899")
		data, err := cli.DownloadFile(torrent, peerAddr)
		if err != nil {
			fmt.Println(err)
			return
		}

		file, err := os.Create(outputFilePath)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		file.Write(data)

		fmt.Printf("Downloaded test.torrent to to %s\n", outputFilePath)
	default:
		fmt.Println("Unknown command: " + command)
	}
}
