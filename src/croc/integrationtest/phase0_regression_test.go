package integrationtest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/schollz/croc/v10/src/codephrase"
	"github.com/schollz/croc/v10/src/croc"
	"github.com/schollz/croc/v10/src/models"
)

const (
	phase0ProbeEnv              = "CROC_PHASE0_OFFLINE_TRANSFER_PROBE"
	phase0Secret                = "p0a1-phase0-transfer-secret-sentinel"
	phase0RejectSecret          = "p0r2-phase0-reject-secret-sentinel"
	phase0UnreachableSecret     = "p0u3-phase0-unreachable-secret-sentinel"
	phase0RelayPassword         = "phase0-relay-password-sentinel-7"
	phase0RejectRelayPassword   = "phase0-reject-relay-password-sentinel-8"
	phase0UnreachablePassword   = "phase0-unreachable-relay-password-sentinel-6"
	phase0CanceledPassword      = "phase0-canceled-relay-password-sentinel-5"
	phase0PayloadSentinel       = "phase0-raw-payload-sentinel-9"
	phase0ManifestNameSentinel  = "phase0-manifest-entry-sentinel.bin"
	phase0UnknownPayloadPrefix  = "test-only-unknown-frame-sentinel"
	phase0StrongKeyLogPrefix    = "strongkey:"
	phase0StrongKeyLogPrefixAlt = "strong key:"
)

// TestPhase0OfflineTransfer is deliberately self-spawning. The child executes
// all network activity while the parent checks the child's combined output
// without redirecting process-global stderr inside croc.
func TestPhase0OfflineTransfer(t *testing.T) {
	if os.Getenv(phase0ProbeEnv) != "" {
		runPhase0OfflineTransferProbe(t)
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestPhase0OfflineTransfer$", "-test.count=1", "-test.timeout=30s")
	command.Env = append(os.Environ(),
		phase0ProbeEnv+"=1",
		"GOTOOLCHAIN=local",
		"GOPROXY=off",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("isolated phase 0 regression probe failed")
	}

	forbidden := []string{
		phase0RelayPassword,
		phase0RejectRelayPassword,
		phase0UnreachablePassword,
		phase0CanceledPassword,
		phase0PayloadSentinel,
		phase0UnknownPayloadPrefix,
		phase0StrongKeyLogPrefix,
		phase0StrongKeyLogPrefixAlt,
		"starting with password",
		"sending password",
		"dataMessage:",
		"decrypted:",
		"https://getcroc.com/",
	}
	for _, secret := range []string{phase0Secret, phase0RejectSecret, phase0UnreachableSecret} {
		components, err := codephrase.Parse(secret)
		if err != nil {
			t.Fatal("parse test-only transfer phrase")
		}
		forbidden = append(forbidden, secret, components.PAKEPassphrase, components.RoomName)
	}
	for _, value := range forbidden {
		if bytes.Contains(output, []byte(value)) {
			t.Fatal("phase 0 process output contained forbidden sensitive data")
		}
	}
}

func runPhase0OfflineTransferProbe(t *testing.T) {
	t.Run("successful multi-file transfer", runPhase0SuccessfulTransfer)
	t.Run("manifest rejection", runPhase0ManifestRejection)
	t.Run("unreachable custom relay", runPhase0UnreachableRelay)
	t.Run("cancel waiting peer", TestCancellationWaitingPeerResourceLifecycle)
	t.Run("cancel securing", TestCancellationSecuringClosesFakePeer)
	t.Run("cancel awaiting approval", TestCancellationAwaitingApprovalResourceLifecycle)
	t.Run("cancel transferring", TestCancellationTransferringResourceLifecycle)
	t.Run("cancel reconnect backoff", TestCancellationReconnectBackoffResourceLifecycle)
}

func runPhase0SuccessfulTransfer(t *testing.T) {
	relay := startLoopbackRelayWithDataPortsAndPassword(t, 2, phase0RelayPassword)
	receiveDir, files, folders, folderCount, sourceHashes, totalBytes := createPhase0Fixture(t)
	changeWorkingDirectory(t, receiveDir)

	manifestSeen := make(chan croc.ReceiveManifest, 1)
	approver := croc.ManifestApproverFunc(func(_ context.Context, manifest croc.ReceiveManifest) (croc.ManifestDecision, error) {
		manifestSeen <- manifest
		if len(manifest.Entries) > 0 {
			manifest.Entries[0].Path = "mutated-test-only-path"
		}
		return croc.ManifestAccept, nil
	})
	recorder := new(integrationEventRecorder)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sender, receiver := newTransferClients(t, relay, phase0Secret, ctx, ctx, approver)
	sender.Options.NoMultiplexing = false
	receiver.Options.NoMultiplexing = false
	receiver.Options.EventSink = croc.EventSinkFunc(recorder.sink)

	senderErr, receiverErr := runTransferPair(t, sender, receiver, files, folders, folderCount)
	if senderErr != nil || receiverErr != nil {
		t.Fatal("phase 0 loopback transfer failed")
	}
	if !sender.SuccessfulTransfer || !receiver.SuccessfulTransfer {
		t.Fatal("successful loopback transfer did not report success")
	}
	if len(sender.Options.RelayPorts) != 2 || len(receiver.Options.RelayPorts) != 2 {
		t.Fatal("phase 0 transfer did not use both relay data ports")
	}

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer drainCancel()
	if err := receiver.WaitForEventDrain(drainCtx); err != nil {
		t.Fatal("phase 0 event dispatcher did not drain")
	}
	assertPhase0CompletedEvents(t, recorder.snapshot(), len(files), totalBytes)

	select {
	case manifest := <-manifestSeen:
		if manifest.Count != len(files) || manifest.FileCount != len(files) || manifest.TotalBytes != totalBytes {
			t.Fatal("phase 0 approver did not receive the complete manifest")
		}
		for _, entry := range manifest.Entries {
			if entry.Type != croc.ManifestEntryFile || filepath.IsAbs(entry.Path) || strings.Contains(entry.Path, "..") {
				t.Fatal("phase 0 approver received an unsafe manifest entry")
			}
		}
	default:
		t.Fatal("phase 0 approver was not called")
	}

	for _, file := range files {
		name := filepath.Base(file.Name)
		targetData, err := os.ReadFile(filepath.Join(receiveDir, name))
		if err != nil {
			t.Fatal("read phase 0 received file")
		}
		if got := sha256.Sum256(targetData); got != sourceHashes[name] {
			t.Fatal("phase 0 source and target SHA-256 differ")
		}
	}
}

func createPhase0Fixture(t *testing.T) (string, []croc.FileInfo, []croc.FileInfo, int, map[string][sha256.Size]byte, int64) {
	t.Helper()
	root := t.TempDir()
	sourceDir := filepath.Join(root, "source")
	receiveDir := filepath.Join(root, "receive")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal("create phase 0 source directory")
	}
	if err := os.MkdirAll(receiveDir, 0o755); err != nil {
		t.Fatal("create phase 0 receive directory")
	}

	chunkSize := models.TCP_BUFFER_SIZE / 2
	names := []string{phase0ManifestNameSentinel, "phase0-beta.bin", "phase0-gamma.bin"}
	sizes := []int{3*chunkSize + 17, 2*chunkSize + 9, chunkSize + 3}
	paths := make([]string, 0, len(names))
	hashes := make(map[string][sha256.Size]byte, len(names))
	var totalBytes int64
	for index, name := range names {
		payload := bytes.Repeat([]byte{byte(index + 1)}, sizes[index])
		copy(payload, []byte(fmt.Sprintf("%s-%d", phase0PayloadSentinel, index)))
		path := filepath.Join(sourceDir, name)
		if err := os.WriteFile(path, payload, 0o640); err != nil {
			t.Fatal("create phase 0 source file")
		}
		paths = append(paths, path)
		hashes[name] = sha256.Sum256(payload)
		totalBytes += int64(len(payload))
	}
	files, folders, folderCount, err := croc.GetFilesInfo(paths, false, false, nil)
	if err != nil {
		t.Fatal("collect phase 0 source metadata")
	}
	return receiveDir, files, folders, folderCount, hashes, totalBytes
}

func assertPhase0CompletedEvents(t *testing.T, events []croc.TransferEvent, fileCount int, totalBytes int64) {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("phase 0 event stream was empty")
	}
	lastSequence := uint64(0)
	lastTotal := int64(0)
	lastFile := make(map[int]int64)
	started := make(map[int]bool)
	completed := make(map[int]bool)
	manifestReady := false
	for _, event := range events {
		if event.Sequence <= lastSequence {
			t.Fatal("phase 0 event sequence was not strictly increasing")
		}
		lastSequence = event.Sequence
		switch event.Type {
		case croc.TransferEventManifestReady:
			manifestReady = event.Manifest != nil && event.Manifest.Count == fileCount && event.Manifest.TotalBytes == totalBytes
		case croc.TransferEventFileStarted:
			started[event.FileIndex] = true
		case croc.TransferEventProgress:
			if event.FileBytesTransferred < lastFile[event.FileIndex] || event.FileBytesTransferred > event.FileSize {
				t.Fatal("phase 0 per-file progress was not monotonic and bounded")
			}
			if event.TotalBytesTransferred < lastTotal || event.TotalBytesTransferred > totalBytes {
				t.Fatal("phase 0 task progress was not monotonic and bounded")
			}
			lastFile[event.FileIndex] = event.FileBytesTransferred
			lastTotal = event.TotalBytesTransferred
		case croc.TransferEventFileCompleted:
			completed[event.FileIndex] = true
		}
	}
	terminal := events[len(events)-1]
	if terminal.Type != croc.TransferEventTerminal || terminal.TerminalState != croc.TransferTerminalCompleted {
		t.Fatal("phase 0 event stream did not terminate as completed")
	}
	if !manifestReady || len(started) != fileCount || len(completed) != fileCount || lastTotal != totalBytes {
		t.Fatal("phase 0 event stream did not cover the complete transfer lifecycle")
	}
}

func runPhase0ManifestRejection(t *testing.T) {
	relay := startLoopbackRelayWithDataPortsAndPassword(t, 1, phase0RejectRelayPassword)
	sourcePath, receiveDir, files, folders, folderCount := createTransferFixture(t)
	changeWorkingDirectory(t, receiveDir)
	recorder := new(integrationEventRecorder)
	approver := croc.ManifestApproverFunc(func(_ context.Context, _ croc.ReceiveManifest) (croc.ManifestDecision, error) {
		return croc.ManifestReject, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sender, receiver := newTransferClients(t, relay, phase0RejectSecret, ctx, ctx, approver)
	receiver.Options.EventSink = croc.EventSinkFunc(recorder.sink)

	senderErr, receiverErr := runTransferPair(t, sender, receiver, files, folders, folderCount)
	if senderErr == nil || receiverErr == nil || !strings.Contains(senderErr.Error(), "refusing files") || !strings.Contains(receiverErr.Error(), "refused files") {
		t.Fatal("phase 0 manifest rejection did not use the existing protocol error")
	}
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer drainCancel()
	if err := receiver.WaitForEventDrain(drainCtx); err != nil {
		t.Fatal("phase 0 rejected event stream did not drain")
	}
	events := recorder.snapshot()
	if len(events) == 0 || events[len(events)-1].Type != croc.TransferEventTerminal || events[len(events)-1].TerminalState != croc.TransferTerminalRejected {
		t.Fatal("phase 0 rejection did not publish a rejected terminal event")
	}
	if _, err := os.Lstat(filepath.Join(receiveDir, filepath.Base(sourcePath))); !os.IsNotExist(err) {
		t.Fatal("phase 0 rejected manifest created a target file")
	}
}

func runPhase0UnreachableRelay(t *testing.T) {
	port := unusedLoopbackPort(t)
	relay := loopbackRelay{
		address:  "127.0.0.1:" + port,
		password: phase0UnreachablePassword,
	}
	_, _, files, folders, folderCount := createTransferFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	options := transferOptions(relay, phase0UnreachableSecret)
	options.IsSender = true
	sender, err := croc.NewCtx(ctx, options)
	if err != nil {
		t.Fatal("create phase 0 unreachable-relay sender")
	}
	started := time.Now()
	if err := sender.Send(files, folders, folderCount); err == nil {
		t.Fatal("unreachable custom relay unexpectedly connected")
	}
	if time.Since(started) > time.Second {
		t.Fatal("unreachable custom relay did not fail promptly")
	}
	if sender.Options.RelayAddress6 != "" || sender.Options.RelayAddress != relay.address {
		t.Fatal("unreachable custom relay changed to a fallback address")
	}
}

func TestPhase0CancellationErrorsRemainIdentifiable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client, err := croc.NewCtx(ctx, croc.Options{
		SharedSecret:             phase0UnreachableSecret,
		RelayAddress:             "127.0.0.1:" + unusedLoopbackPort(t),
		RelayPassword:            phase0CanceledPassword,
		DisableLocal:             true,
		NoPrompt:                 true,
		Curve:                    "siec",
		SuppressSendInstructions: true,
	})
	if err != nil {
		t.Fatal("create pre-canceled phase 0 client")
	}
	if err := client.Receive(); !errors.Is(err, context.Canceled) {
		t.Fatal("phase 0 cancellation was not identifiable")
	}
}
