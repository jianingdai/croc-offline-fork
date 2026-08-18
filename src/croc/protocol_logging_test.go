package croc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/schollz/logger"

	"github.com/schollz/croc/v10/src/comm"
	"github.com/schollz/croc/v10/src/crypt"
	"github.com/schollz/croc/v10/src/message"
	"github.com/schollz/croc/v10/src/pakekey"
)

const (
	protocolMessageLogProbeEnv = "CROC_PROTOCOL_MESSAGE_LOG_PROBE"
	probeSecret                = "8123-protocol-log-probe"
	probeManifest              = "test-only-manifest-sentinel.txt"
	probeHash                  = "test-only-hash-sentinel"
	probeExternalIP            = "test-only-external-ip-sentinel"
	probeUnknown               = "test-only-unknown-frame-sentinel"
	probeCiphertext            = "test-only-ciphertext-sentinel"
	probePlaintext             = "test-only-plaintext-sentinel"
	probeRawProtocol           = "test-only-raw-protocol-sentinel"
)

func TestProtocolMessageLogs(t *testing.T) {
	if os.Getenv(protocolMessageLogProbeEnv) != "" {
		runProtocolMessageLogProbe(t)
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestProtocolMessageLogs$")
	command.Env = append(os.Environ(), protocolMessageLogProbeEnv+"=1")
	command.Stderr = io.Discard
	output, err := command.Output()
	if err != nil {
		t.Fatal("isolated protocol logging probe failed")
	}

	logs := string(output)
	forbidden := []string{
		probeManifest,
		probeExternalIP,
		probeUnknown,
		probeCiphertext,
		probePlaintext,
		probeRawProtocol,
		fmt.Sprint([]byte(probeHash)),
		"dataMessage:",
		"decrypted:",
		"ips data:",
		"received external IP:",
		"current file chunks:",
		"file 0 info:",
		"hashes are not equal",
	}
	for _, value := range forbidden {
		if strings.Contains(logs, value) {
			t.Fatal("protocol logs contained forbidden dynamic payload data")
		}
	}

	for _, event := range []string{
		"hashed file 0",
		"received file manifest metadata",
		"received external IP message",
		"local probe frame received",
		"local probe plaintext decoded",
		"local probe decryption failed",
		"unexpected local probe message",
		"protocol frame processing failed",
		"received requested file chunks",
	} {
		if !strings.Contains(logs, event) {
			t.Fatalf("protocol logs omitted fixed diagnostic event %q", event)
		}
	}
}

func runProtocolMessageLogProbe(t *testing.T) {
	t.Helper()
	log.SetOutput(os.Stdout)
	log.SetLevel("trace")

	probeCollectedFileLogs(t)
	client := probeClient(t, false)
	probeManifestLogs(t, client)
	probeExternalIPLogs(t, client)
	probeRecipientReadyLogs(t, client)
	probeLocalHandshakeLogs(t, []byte(probePlaintext), true)
	probeLocalHandshakeLogs(t, []byte(probeCiphertext), false)
	probeUnknownLocalFrameLogs(t)
	probeRawTransferLogs(t)
}

func probeClient(t *testing.T, sender bool) *Client {
	t.Helper()
	client, err := New(Options{
		IsSender:                 sender,
		SharedSecret:             probeSecret,
		NoPrompt:                 true,
		DisableLocal:             true,
		Curve:                    "siec",
		HashAlgorithm:            "xxhash",
		SuppressSendInstructions: true,
	})
	if err != nil {
		t.Fatal("create protocol logging probe client")
	}
	log.SetLevel("trace")
	return client
}

func probeCollectedFileLogs(t *testing.T) {
	t.Helper()
	client := probeClient(t, true)
	fileName := filepath.Join(t.TempDir(), probeManifest)
	if err := os.WriteFile(fileName, []byte("test-only-file-content"), 0o600); err != nil {
		t.Fatal("create protocol logging probe file")
	}
	files, emptyFolders, totalFolders, err := GetFilesInfo([]string{fileName}, false, false, nil)
	if err != nil {
		t.Fatal("collect protocol logging probe file")
	}
	client.EmptyFoldersToTransfer = emptyFolders
	client.TotalNumberFolders = totalFolders
	if err := client.sendCollectFiles(files); err != nil {
		t.Fatal("hash protocol logging probe file")
	}
}

func probeManifestLogs(t *testing.T, client *Client) {
	t.Helper()
	payload, err := json.Marshal(SenderInfo{
		FilesToTransfer: []FileInfo{{
			Name:         probeManifest,
			FolderRemote: ".",
			Hash:         []byte(probeHash),
			Size:         1,
			Mode:         0o600,
		}},
		HashAlgorithm: "xxhash",
	})
	if err != nil {
		t.Fatal("encode protocol logging manifest")
	}
	if _, err := client.processMessageFileInfo(message.Message{Bytes: payload}); err != nil {
		t.Fatal("process protocol logging manifest")
	}
}

func probeExternalIPLogs(t *testing.T, client *Client) {
	t.Helper()
	if _, err := client.processExternalIP(message.Message{
		Type:    message.TypeExternalIP,
		Message: probeExternalIP,
		Bytes:   []byte("test-only-pake-transcript"),
	}); err != nil {
		t.Fatal("process protocol logging external IP message")
	}
}

func probeRecipientReadyLogs(t *testing.T, client *Client) {
	t.Helper()
	payload, err := json.Marshal(RemoteFileRequest{
		CurrentFileChunkRanges:    []int64{65536, 424242, 2},
		FilesToTransferCurrentNum: 0,
	})
	if err != nil {
		t.Fatal("encode protocol logging file request")
	}
	key := []byte("01234567890123456789012345678901")
	encoded, err := message.Encode(key, message.Message{Type: message.TypeRecipientReady, Bytes: payload})
	if err != nil {
		t.Fatal("encode protocol logging message")
	}
	client.Key = key
	if _, err := client.processMessage(encoded, &transferAttemptState{errc: make(chan error, 1)}); err != nil {
		t.Fatal("process protocol logging file request")
	}
}

func probeLocalHandshakeLogs(t *testing.T, finalPayload []byte, encryptPayload bool) {
	t.Helper()
	client := probeClient(t, true)
	serverSide, peerSide := net.Pipe()
	server := comm.New(serverSide)
	peer := comm.New(peerSide)
	defer server.Close()
	defer peer.Close()

	errChan := make(chan error, 1)
	go func() {
		errChan <- client.senderWaitForHandshake(server)
	}()

	initiatorPAKE, err := pakekey.Init(
		[]byte(client.pakePassphrase),
		0,
		client.Options.Curve,
		pakekey.PurposeLocalProbe,
		client.Options.RoomName,
	)
	if err != nil {
		t.Fatal("initialize local logging probe PAKE")
	}
	initiator := append([]byte(nil), initiatorPAKE.Bytes()...)
	request, err := json.Marshal(SimpleMessage{
		Bytes:   initiator,
		Kind:    "pake1",
		Version: pakekey.ProtocolVersion,
		Curve:   client.Options.Curve,
	})
	if err != nil || peer.Send(request) != nil {
		t.Fatal("send local logging probe PAKE request")
	}
	responseBytes, err := peer.Receive()
	if err != nil {
		t.Fatal("receive local logging probe PAKE response")
	}
	var response SimpleMessage
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		t.Fatal("decode local logging probe PAKE response")
	}
	if err := initiatorPAKE.Update(response.Bytes); err != nil {
		t.Fatal("update local logging probe PAKE")
	}
	sharedKey, err := initiatorPAKE.SessionKey()
	if err != nil {
		t.Fatal("derive local logging probe session key")
	}
	keys, err := pakekey.Derive(sharedKey, pakekey.Context{
		Purpose:   pakekey.PurposeLocalProbe,
		Room:      client.Options.RoomName,
		Curve:     client.Options.Curve,
		Initiator: initiator,
		Responder: response.Bytes,
		Salt:      response.Bytes2,
	})
	if err != nil {
		t.Fatal("derive local logging probe encryption key")
	}

	payload := finalPayload
	if encryptPayload {
		payload, err = crypt.Encrypt(finalPayload, keys.EncryptionKey)
		if err != nil {
			t.Fatal("encrypt local logging probe payload")
		}
	}
	if err := peer.Send(payload); err != nil {
		t.Fatal("send local logging probe payload")
	}
	select {
	case <-errChan:
	case <-time.After(time.Second):
		t.Fatal("local logging probe did not finish")
	}
}

func probeUnknownLocalFrameLogs(t *testing.T) {
	t.Helper()
	client := probeClient(t, true)
	serverSide, peerSide := net.Pipe()
	server := comm.New(serverSide)
	peer := comm.New(peerSide)
	defer server.Close()
	defer peer.Close()

	errChan := make(chan error, 1)
	go func() {
		errChan <- client.senderWaitForHandshake(server)
	}()
	if err := peer.Send([]byte(probeUnknown)); err != nil {
		t.Fatal("send unknown local logging probe frame")
	}
	select {
	case <-errChan:
	case <-time.After(time.Second):
		t.Fatal("unknown local logging probe did not finish")
	}
}

func probeRawTransferLogs(t *testing.T) {
	t.Helper()
	client := probeClient(t, true)
	serverSide, peerSide := net.Pipe()
	server := comm.New(serverSide)
	peer := comm.New(peerSide)
	defer server.Close()
	defer peer.Close()
	client.conn[0] = server
	client.stop = newStop(context.Background())

	go func() {
		_ = peer.Send([]byte(probeRawProtocol))
	}()
	if err := client.transfer(); err == nil {
		t.Fatal("raw protocol logging probe unexpectedly succeeded")
	}
}
