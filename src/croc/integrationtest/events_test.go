package integrationtest

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/schollz/croc/v10/src/croc"
	"github.com/schollz/croc/v10/src/models"
)

type integrationEventRecorder struct {
	mu     sync.Mutex
	events []croc.TransferEvent
}

func (r *integrationEventRecorder) sink(event croc.TransferEvent) {
	// A deliberately non-zero callback duration exercises the asynchronous
	// dispatcher without making the transfer depend on sink throughput.
	time.Sleep(2 * time.Millisecond)
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
}

func (r *integrationEventRecorder) snapshot() []croc.TransferEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]croc.TransferEvent(nil), r.events...)
}

func createMultiFileFixture(t *testing.T) (string, []croc.FileInfo, []croc.FileInfo, int, int64) {
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
	chunkSize := models.TCP_BUFFER_SIZE / 2
	sizes := []int{3*chunkSize + 17, 2*chunkSize + 9, chunkSize + 3}
	paths := make([]string, 0, len(sizes))
	var totalBytes int64
	for i, size := range sizes {
		name := filepath.Join(sourceDir, []string{"alpha.bin", "beta.bin", "gamma.bin"}[i])
		payload := bytes.Repeat([]byte{byte(i + 1)}, size)
		if err := os.WriteFile(name, payload, 0o640); err != nil {
			t.Fatalf("create source file: %v", err)
		}
		paths = append(paths, name)
		totalBytes += int64(size)
	}
	files, folders, folderCount, err := croc.GetFilesInfo(paths, false, false, nil)
	if err != nil {
		t.Fatalf("collect source metadata: %v", err)
	}
	return receiveDir, files, folders, folderCount, totalBytes
}

func TestStructuredEventsMultiFileProgressAndEventDrain(t *testing.T) {
	relay := startLoopbackRelayWithDataPorts(t, 2)
	receiveDir, files, folders, folderCount, totalBytes := createMultiFileFixture(t)
	changeWorkingDirectory(t, receiveDir)
	recorder := new(integrationEventRecorder)
	approver := croc.ManifestApproverFunc(func(_ context.Context, _ croc.ReceiveManifest) (croc.ManifestDecision, error) {
		return croc.ManifestAccept, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sender, receiver := newTransferClients(t, relay, testSecret(t), ctx, ctx, approver)
	sender.Options.NoMultiplexing = false
	receiver.Options.NoMultiplexing = false
	receiver.Options.EventSink = croc.EventSinkFunc(recorder.sink)

	senderErr, receiverErr := runTransferPair(t, sender, receiver, files, folders, folderCount)
	if senderErr != nil || receiverErr != nil {
		t.Fatalf("structured-event transfer failed: sender=%v receiver=%v", senderErr, receiverErr)
	}
	if len(sender.Options.RelayPorts) != 2 || len(receiver.Options.RelayPorts) != 2 {
		t.Fatal("test did not exercise both relay data ports")
	}
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer drainCancel()
	if err := receiver.WaitForEventDrain(drainCtx); err != nil {
		t.Fatalf("wait for terminal event drain: %v", err)
	}
	if err := receiver.WaitForEventDrain(drainCtx); err != nil {
		t.Fatalf("repeat terminal event drain: %v", err)
	}

	events := recorder.snapshot()
	if len(events) == 0 {
		t.Fatal("event sink received no events")
	}
	for i := 1; i < len(events); i++ {
		if events[i].Sequence <= events[i-1].Sequence {
			t.Fatal("event sequence is not strictly increasing")
		}
	}
	if events[0].Type != croc.TransferEventPhase || events[0].Phase != croc.TransferPhaseConnecting {
		t.Fatal("event stream did not begin in connecting phase")
	}
	terminal := events[len(events)-1]
	if terminal.Type != croc.TransferEventTerminal || terminal.TerminalState != croc.TransferTerminalCompleted {
		t.Fatal("event stream did not end with completed terminal state")
	}

	requiredTypes := map[croc.TransferEventType]bool{
		croc.TransferEventPhase:         false,
		croc.TransferEventManifestReady: false,
		croc.TransferEventFileStarted:   false,
		croc.TransferEventProgress:      false,
		croc.TransferEventFileCompleted: false,
		croc.TransferEventTerminal:      false,
	}
	requiredPhases := map[croc.TransferPhase]bool{
		croc.TransferPhaseConnecting:       false,
		croc.TransferPhaseSecuring:         false,
		croc.TransferPhaseAwaitingApproval: false,
		croc.TransferPhaseTransferring:     false,
		croc.TransferPhaseFinalizing:       false,
	}
	startedFiles := make(map[int]int)
	completedFiles := make(map[int]int)
	lastFileBytes := make(map[int]int64)
	lastTotalBytes := int64(0)
	lastProgressTotal := int64(0)
	manifestCount := 0
	for _, event := range events {
		if _, ok := requiredTypes[event.Type]; ok {
			requiredTypes[event.Type] = true
		}
		if event.Type == croc.TransferEventPhase {
			if _, ok := requiredPhases[event.Phase]; ok {
				requiredPhases[event.Phase] = true
			}
		}
		if event.Type == croc.TransferEventManifestReady {
			manifestCount++
			if event.Manifest == nil || event.Manifest.Count != len(files) || event.Manifest.TotalBytes != totalBytes {
				t.Fatal("manifest-ready event did not contain the complete safe snapshot")
			}
		}
		if event.Type == croc.TransferEventFileStarted {
			startedFiles[event.FileIndex]++
		}
		if event.Type == croc.TransferEventFileCompleted {
			completedFiles[event.FileIndex]++
		}
		if event.Type == croc.TransferEventProgress {
			if event.FileBytesTransferred < lastFileBytes[event.FileIndex] || event.FileBytesTransferred > event.FileSize {
				t.Fatal("per-file progress is not monotonic and bounded")
			}
			if event.TotalBytesTransferred < lastTotalBytes || event.TotalBytesTransferred > event.TotalBytes {
				t.Fatal("task progress is not monotonic and bounded")
			}
			lastFileBytes[event.FileIndex] = event.FileBytesTransferred
			lastTotalBytes = event.TotalBytesTransferred
			lastProgressTotal = event.TotalBytesTransferred
		}
	}
	for eventType, seen := range requiredTypes {
		if !seen {
			t.Fatalf("missing required event type %s", eventType)
		}
	}
	for phase, seen := range requiredPhases {
		if !seen {
			t.Fatalf("missing required transfer phase %s", phase)
		}
	}
	if manifestCount != 1 {
		t.Fatal("manifest-ready event was not emitted exactly once")
	}
	if len(startedFiles) != len(files) || len(completedFiles) != len(files) {
		t.Fatal("file lifecycle events did not cover every file")
	}
	for i := range files {
		if startedFiles[i] != 1 || completedFiles[i] != 1 {
			t.Fatal("a file lifecycle event was duplicated or omitted")
		}
	}
	if lastProgressTotal != totalBytes {
		t.Fatal("final task progress did not reach total bytes")
	}
}
