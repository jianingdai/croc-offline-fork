package croc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/schollz/croc/v10/src/models"
)

type transferEventRecorder struct {
	mu     sync.Mutex
	events []TransferEvent
}

func (r *transferEventRecorder) record(event TransferEvent) {
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
}

func (r *transferEventRecorder) snapshot() []TransferEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]TransferEvent(nil), r.events...)
}

func TestEventDispatcherConcurrentSequenceAndDrain(t *testing.T) {
	recorder := new(transferEventRecorder)
	client := &Client{Options: Options{EventSink: EventSinkFunc(recorder.record)}}
	client.emitPhase(TransferPhaseConnecting)

	const goroutines = 8
	const eventsPerGoroutine = 25
	var wait sync.WaitGroup
	wait.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wait.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				client.emitPhase(TransferPhaseSecuring)
			}
		}()
	}
	wait.Wait()
	client.emitReconnect(1)
	client.SuccessfulTransfer = true
	client.finishTransferEvents(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.WaitForEventDrain(ctx); err != nil {
		t.Fatalf("wait for event drain: %v", err)
	}
	if err := client.WaitForEventDrain(ctx); err != nil {
		t.Fatalf("repeat event drain: %v", err)
	}

	events := recorder.snapshot()
	wantCount := 1 + goroutines*eventsPerGoroutine + 1 + 2
	if len(events) != wantCount {
		t.Fatalf("got %d lifecycle events, want %d", len(events), wantCount)
	}
	for i, event := range events {
		wantSequence := uint64(i + 1)
		if event.Sequence != wantSequence {
			t.Fatalf("event %d has sequence %d, want %d", i, event.Sequence, wantSequence)
		}
	}
	terminal := events[len(events)-1]
	if terminal.Type != TransferEventTerminal || terminal.TerminalState != TransferTerminalCompleted {
		t.Fatal("terminal event was not delivered last")
	}
	if reconnect := events[len(events)-3]; reconnect.Type != TransferEventReconnect || reconnect.ReconnectAttempt != 1 {
		t.Fatal("reconnect lifecycle event was not retained")
	}
}

func TestEventDrainSlowSinkDoesNotBlockProgress(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var enterOnce sync.Once
	recorder := new(transferEventRecorder)
	client := &Client{Options: Options{EventSink: EventSinkFunc(func(event TransferEvent) {
		enterOnce.Do(func() {
			close(entered)
			<-release
		})
		recorder.record(event)
	})}}
	client.emitPhase(TransferPhaseConnecting)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("slow sink was not called")
	}

	started := time.Now()
	for i := 0; i < 2_000; i++ {
		client.emitTransferEvent(TransferEvent{
			Type:                  TransferEventProgress,
			FileIndex:             0,
			FileBytesTransferred:  int64(i),
			TotalBytesTransferred: int64(i),
			TotalBytes:            2_000,
		})
	}
	client.finishTransferEvents(errors.New("test-only failure"))
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("slow sink blocked event producers for %s", elapsed)
	}

	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer timeoutCancel()
	if err := client.WaitForEventDrain(timeoutCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("event drain did not honor its timeout")
	}
	close(release)
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer drainCancel()
	if err := client.WaitForEventDrain(drainCtx); err != nil {
		t.Fatalf("event drain after releasing sink: %v", err)
	}

	events := recorder.snapshot()
	progressCount := 0
	var lastProgress TransferEvent
	for _, event := range events {
		if event.Type == TransferEventProgress {
			progressCount++
			lastProgress = event
		}
	}
	if progressCount == 0 || progressCount >= 2_000 {
		t.Fatal("pending progress events were not coalesced")
	}
	if lastProgress.TotalBytesTransferred != 1_999 {
		t.Fatal("coalescing did not preserve the latest progress")
	}
	if events[len(events)-1].Type != TransferEventTerminal {
		t.Fatal("terminal event was not drained last")
	}
	if progressCount == 1 && lastProgress.Sequence <= 2 {
		t.Fatal("coalesced progress sequence did not preserve its allocation gap")
	}
}

func TestEventDrainNilSinkAndSinkPanic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := (&Client{}).WaitForEventDrain(ctx); err != nil {
		t.Fatalf("nil sink drain: %v", err)
	}
	unused := &Client{Options: Options{EventSink: EventSinkFunc(func(TransferEvent) {})}}
	if err := unused.WaitForEventDrain(ctx); err != nil {
		t.Fatalf("unstarted sink drain: %v", err)
	}

	client := &Client{Options: Options{EventSink: EventSinkFunc(func(TransferEvent) {
		panic("test-only sink panic")
	})}}
	client.emitPhase(TransferPhaseConnecting)
	client.finishTransferEvents(errors.New("test-only failure"))
	if err := client.WaitForEventDrain(ctx); err != nil {
		t.Fatalf("panicking sink prevented dispatcher shutdown: %v", err)
	}
}

func TestProgressTrackerResumeAndDeduplicate(t *testing.T) {
	chunkSize := int64(models.TCP_BUFFER_SIZE / 2)
	fileSize := 3*chunkSize + 10
	tracker := newProgressTracker([]FileInfo{
		{Name: "first.bin", FolderRemote: "nested", Size: fileSize},
		{Name: "second.bin", FolderRemote: ".", Size: 25},
	})

	snapshot, started, changed := tracker.start(0, []int64{chunkSize, 2 * chunkSize})
	if !started || !changed || snapshot.fileBytes != chunkSize+10 || snapshot.totalDone != chunkSize+10 {
		t.Fatal("resume bytes were not included in initial progress")
	}
	snapshot, _, changed = tracker.add(0, chunkSize, int(chunkSize))
	if !changed || snapshot.fileBytes != 2*chunkSize+10 {
		t.Fatal("first missing chunk did not advance progress")
	}
	duplicate, _, changed := tracker.add(0, chunkSize, int(chunkSize))
	if changed || duplicate.fileBytes != snapshot.fileBytes || duplicate.totalDone != snapshot.totalDone {
		t.Fatal("duplicate chunk advanced progress")
	}
	completed, _, ok := tracker.complete(0)
	if !ok || completed.fileBytes != fileSize || completed.totalDone != fileSize {
		t.Fatal("file completion did not reach its exact size")
	}

	second, started, changed := tracker.add(1, 20, 10)
	if !started || !changed || second.fileBytes != 5 {
		t.Fatal("progress was not clamped to the file boundary")
	}
	second, _, changed = tracker.add(1, 0, 20)
	if !changed || second.fileBytes != 25 || second.totalDone != tracker.totalBytes {
		t.Fatal("task progress did not monotonically reach the total size")
	}
}

func TestEventTerminalStatesDoNotExposeErrors(t *testing.T) {
	tests := []struct {
		err        error
		successful bool
		want       TransferTerminalState
	}{
		{successful: true, want: TransferTerminalCompleted},
		{err: fmt.Errorf("refused files"), want: TransferTerminalRejected},
		{err: fmt.Errorf("wrapped: %w", context.Canceled), want: TransferTerminalCanceled},
		{err: errors.New("test-only failure detail"), want: TransferTerminalFailed},
	}
	for _, test := range tests {
		if got := terminalStateFor(test.err, test.successful); got != test.want {
			t.Fatalf("terminal state = %s, want %s", got, test.want)
		}
	}
}
