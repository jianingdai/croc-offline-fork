package integrationtest

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	log "github.com/schollz/logger"

	"github.com/schollz/croc/v10/src/croc"
	"github.com/schollz/croc/v10/src/tcp"
)

func TestMain(m *testing.M) {
	// The upstream logger stores its level in unsynchronized global booleans.
	// Freeze the level before test goroutines start so race tests exercise the
	// transfer APIs without concurrently mutating that known-global state.
	log.SetLevel("error")
	if err := os.Setenv("LOGGER", "error"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

type loopbackRelay struct {
	address  string
	password string
}

func unusedLoopbackPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release loopback port: %v", err)
	}
	return strconv.Itoa(port)
}

func waitForLoopbackListener(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp4", address, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("loopback relay did not listen at %s", address)
}

func startLoopbackRelay(t *testing.T) loopbackRelay {
	t.Helper()
	return startLoopbackRelayWithDataPorts(t, 1)
}

func startLoopbackRelayWithDataPorts(t *testing.T, dataPortCount int) loopbackRelay {
	t.Helper()
	if dataPortCount < 1 {
		t.Fatal("loopback relay needs at least one data port")
	}
	controlPort := unusedLoopbackPort(t)
	dataPorts := make([]string, 0, dataPortCount)
	usedPorts := map[string]struct{}{controlPort: {}}
	for len(dataPorts) < dataPortCount {
		port := unusedLoopbackPort(t)
		if _, exists := usedPorts[port]; exists {
			continue
		}
		usedPorts[port] = struct{}{}
		dataPorts = append(dataPorts, port)
	}
	password := "test-only-relay-password"
	ctx, cancel := context.WithCancel(context.Background())
	serverErrors := make(chan error, dataPortCount+1)
	for _, dataPort := range dataPorts {
		dataPort := dataPort
		go func() {
			serverErrors <- tcp.RunCtx(ctx, "error", "127.0.0.1", dataPort, password)
		}()
		waitForLoopbackListener(t, net.JoinHostPort("127.0.0.1", dataPort))
	}
	go func() {
		serverErrors <- tcp.RunCtx(ctx, "error", "127.0.0.1", controlPort, password, strings.Join(dataPorts, ","))
	}()
	address := net.JoinHostPort("127.0.0.1", controlPort)
	waitForLoopbackListener(t, address)

	t.Cleanup(func() {
		cancel()
		for i := 0; i < dataPortCount+1; i++ {
			select {
			case err := <-serverErrors:
				if err != nil {
					t.Errorf("stop loopback relay: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("loopback relay did not stop")
			}
		}
	})
	return loopbackRelay{address: address, password: password}
}

func changeWorkingDirectory(t *testing.T, directory string) {
	t.Helper()
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
}

func createTransferFixture(t *testing.T) (string, string, []croc.FileInfo, []croc.FileInfo, int) {
	t.Helper()
	root := t.TempDir()
	sourceDir := filepath.Join(root, "source")
	receiveDir := filepath.Join(root, "receive")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatalf("create source directory: %v", err)
	}
	if err := os.MkdirAll(receiveDir, 0o755); err != nil {
		t.Fatalf("create receive directory: %v", err)
	}
	sourcePath := filepath.Join(sourceDir, "approval-payload.txt")
	if err := os.WriteFile(sourcePath, []byte("test-only-approval-payload"), 0o640); err != nil {
		t.Fatalf("create source file: %v", err)
	}
	files, folders, folderCount, err := croc.GetFilesInfo([]string{sourcePath}, false, false, nil)
	if err != nil {
		t.Fatalf("collect source metadata: %v", err)
	}
	return sourcePath, receiveDir, files, folders, folderCount
}

func newTransferClients(
	t *testing.T,
	relay loopbackRelay,
	secret string,
	senderCtx context.Context,
	receiverCtx context.Context,
	approver croc.ManifestApprover,
) (*croc.Client, *croc.Client) {
	t.Helper()
	common := croc.Options{
		SharedSecret:             secret,
		RelayAddress:             relay.address,
		RelayPassword:            relay.password,
		NoPrompt:                 true,
		NoMultiplexing:           true,
		DisableLocal:             true,
		Curve:                    "siec",
		Overwrite:                true,
		NoCompress:               true,
		DisableClipboard:         true,
		SuppressSendInstructions: true,
	}
	senderOptions := common
	senderOptions.IsSender = true
	sender, err := croc.NewCtx(senderCtx, senderOptions)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	receiverOptions := common
	receiverOptions.ManifestApprover = approver
	receiver, err := croc.NewCtx(receiverCtx, receiverOptions)
	if err != nil {
		t.Fatalf("create receiver: %v", err)
	}
	return sender, receiver
}

type transferResult struct {
	role string
	err  error
}

func runTransferPair(
	t *testing.T,
	sender *croc.Client,
	receiver *croc.Client,
	files []croc.FileInfo,
	folders []croc.FileInfo,
	folderCount int,
) (error, error) {
	t.Helper()
	results := make(chan transferResult, 2)
	go func() {
		results <- transferResult{role: "sender", err: sender.Send(files, folders, folderCount)}
	}()
	go func() {
		results <- transferResult{role: "receiver", err: receiver.Receive()}
	}()

	var senderErr, receiverErr error
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			if result.role == "sender" {
				senderErr = result.err
			} else {
				receiverErr = result.err
			}
		case <-time.After(10 * time.Second):
			t.Fatal("loopback transfer did not finish")
		}
	}
	return senderErr, receiverErr
}

func testSecret(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("approval-test-%d", time.Now().UnixNano())
}
