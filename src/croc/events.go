package croc

import (
	"context"
	"errors"
	"math"
	"path"
	"strings"
	"sync"

	"github.com/schollz/croc/v10/src/models"
)

// EventSink receives serialized transfer events. OnEvent is called by a
// dedicated dispatcher goroutine and never by a transfer goroutine.
type EventSink interface {
	OnEvent(TransferEvent)
}

// EventSinkFunc adapts a function to EventSink.
type EventSinkFunc func(TransferEvent)

// OnEvent calls f(event).
func (f EventSinkFunc) OnEvent(event TransferEvent) {
	f(event)
}

// TransferEventType identifies a structured transfer event.
type TransferEventType string

const (
	TransferEventPhase         TransferEventType = "phase"
	TransferEventManifestReady TransferEventType = "manifest_ready"
	TransferEventFileStarted   TransferEventType = "file_started"
	TransferEventProgress      TransferEventType = "progress"
	TransferEventFileCompleted TransferEventType = "file_completed"
	TransferEventReconnect     TransferEventType = "reconnect"
	TransferEventTerminal      TransferEventType = "terminal"
)

// TransferPhase is a non-sensitive lifecycle phase.
type TransferPhase string

const (
	TransferPhaseConnecting       TransferPhase = "connecting"
	TransferPhaseSecuring         TransferPhase = "securing"
	TransferPhaseAwaitingApproval TransferPhase = "awaiting_approval"
	TransferPhaseTransferring     TransferPhase = "transferring"
	TransferPhaseReconnecting     TransferPhase = "reconnecting"
	TransferPhaseFinalizing       TransferPhase = "finalizing"
)

// TransferTerminalState is the final, non-sensitive transfer outcome.
type TransferTerminalState string

const (
	TransferTerminalCompleted TransferTerminalState = "completed"
	TransferTerminalRejected  TransferTerminalState = "rejected"
	TransferTerminalCanceled  TransferTerminalState = "canceled"
	TransferTerminalFailed    TransferTerminalState = "failed"
)

// TransferEvent is a structured, non-sensitive transfer lifecycle event.
// Fields unrelated to Type are left at their zero value.
type TransferEvent struct {
	Sequence              uint64
	Type                  TransferEventType
	Phase                 TransferPhase
	Manifest              *ReceiveManifest
	FileIndex             int
	FilePath              string
	FileSize              int64
	FileBytesTransferred  int64
	TotalBytesTransferred int64
	TotalBytes            int64
	ReconnectAttempt      int
	TerminalState         TransferTerminalState
}

type eventDispatcher struct {
	sink EventSink

	mu           sync.Mutex
	cond         *sync.Cond
	queue        []TransferEvent
	nextSequence uint64
	started      bool
	sealed       bool
	drained      chan struct{}
}

func newEventDispatcher(sink EventSink) *eventDispatcher {
	dispatcher := &eventDispatcher{
		sink:    sink,
		drained: make(chan struct{}),
	}
	dispatcher.cond = sync.NewCond(&dispatcher.mu)
	return dispatcher
}

func (d *eventDispatcher) enqueue(event TransferEvent) bool {
	if d == nil || d.sink == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sealed {
		return false
	}
	d.nextSequence++
	event.Sequence = d.nextSequence
	if event.Type == TransferEventProgress && len(d.queue) > 0 && d.queue[len(d.queue)-1].Type == TransferEventProgress {
		d.queue[len(d.queue)-1] = event
	} else {
		d.queue = append(d.queue, event)
	}
	if event.Type == TransferEventTerminal {
		d.sealed = true
	}
	if !d.started {
		d.started = true
		go d.run()
	}
	d.cond.Signal()
	return true
}

func (d *eventDispatcher) run() {
	for {
		d.mu.Lock()
		for len(d.queue) == 0 && !d.sealed {
			d.cond.Wait()
		}
		if len(d.queue) == 0 && d.sealed {
			d.mu.Unlock()
			close(d.drained)
			return
		}
		event := d.queue[0]
		d.queue[0] = TransferEvent{}
		d.queue = d.queue[1:]
		d.mu.Unlock()

		func() {
			defer func() {
				_ = recover()
			}()
			d.sink.OnEvent(event)
		}()
	}
}

func (d *eventDispatcher) wait(ctx context.Context) error {
	if d == nil || d.sink == nil {
		return nil
	}
	d.mu.Lock()
	if !d.started {
		d.mu.Unlock()
		return nil
	}
	drained := d.drained
	d.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type fileProgress struct {
	path      string
	size      int64
	bytes     int64
	seen      map[int64]int64
	started   bool
	completed bool
}

type progressTracker struct {
	mu         sync.Mutex
	files      []fileProgress
	totalBytes int64
	totalDone  int64
}

type progressSnapshot struct {
	fileIndex int
	filePath  string
	fileSize  int64
	fileBytes int64
	totalDone int64
	totalSize int64
}

func newProgressTracker(files []FileInfo) *progressTracker {
	tracker := &progressTracker{files: make([]fileProgress, len(files))}
	for i, file := range files {
		size := file.Size
		if size < 0 {
			size = 0
		}
		if size > math.MaxInt64-tracker.totalBytes {
			tracker.totalBytes = math.MaxInt64
		} else if tracker.totalBytes != math.MaxInt64 {
			tracker.totalBytes += size
		}
		tracker.files[i] = fileProgress{
			path: transferEventPath(file),
			size: size,
			seen: make(map[int64]int64),
		}
	}
	return tracker
}

func transferEventPath(file FileInfo) string {
	folder := path.Clean(strings.ReplaceAll(file.FolderRemote, "\\", "/"))
	name := path.Base(strings.ReplaceAll(file.Name, "\\", "/"))
	return path.Clean(path.Join(folder, name))
}

func (p *progressTracker) snapshot(index int) progressSnapshot {
	file := p.files[index]
	return progressSnapshot{
		fileIndex: index,
		filePath:  file.path,
		fileSize:  file.size,
		fileBytes: file.bytes,
		totalDone: p.totalDone,
		totalSize: p.totalBytes,
	}
}

func missingChunkBytes(size int64, positions []int64) int64 {
	seen := make(map[int64]struct{}, len(positions))
	missing := int64(0)
	chunkSize := int64(models.TCP_BUFFER_SIZE / 2)
	for _, position := range positions {
		if position < 0 || position >= size {
			continue
		}
		if _, ok := seen[position]; ok {
			continue
		}
		seen[position] = struct{}{}
		length := chunkSize
		if remaining := size - position; remaining < length {
			length = remaining
		}
		if length > math.MaxInt64-missing {
			return size
		}
		missing += length
		if missing >= size {
			return size
		}
	}
	return missing
}

func (p *progressTracker) start(index int, missingPositions []int64) (progressSnapshot, bool, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if index < 0 || index >= len(p.files) {
		return progressSnapshot{}, false, false
	}
	file := &p.files[index]
	started := !file.started
	file.started = true
	initial := int64(0)
	if len(missingPositions) > 0 {
		initial = file.size - missingChunkBytes(file.size, missingPositions)
	}
	changed := false
	if initial > file.bytes {
		delta := initial - file.bytes
		file.bytes = initial
		p.totalDone += delta
		if p.totalDone > p.totalBytes {
			p.totalDone = p.totalBytes
		}
		changed = true
	}
	return p.snapshot(index), started, changed
}

func (p *progressTracker) add(index int, position int64, count int) (progressSnapshot, bool, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if index < 0 || index >= len(p.files) || count <= 0 {
		return progressSnapshot{}, false, false
	}
	file := &p.files[index]
	started := !file.started
	file.started = true
	if position < 0 || position >= file.size {
		return p.snapshot(index), started, false
	}
	length := int64(count)
	if remaining := file.size - position; length > remaining {
		length = remaining
	}
	previous := file.seen[position]
	if length <= previous {
		return p.snapshot(index), started, false
	}
	file.seen[position] = length
	delta := length - previous
	if delta > file.size-file.bytes {
		delta = file.size - file.bytes
	}
	if delta <= 0 {
		return p.snapshot(index), started, false
	}
	file.bytes += delta
	p.totalDone += delta
	if p.totalDone > p.totalBytes {
		p.totalDone = p.totalBytes
	}
	return p.snapshot(index), started, true
}

func (p *progressTracker) complete(index int) (progressSnapshot, bool, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if index < 0 || index >= len(p.files) {
		return progressSnapshot{}, false, false
	}
	file := &p.files[index]
	started := !file.started
	file.started = true
	if file.completed {
		return p.snapshot(index), started, false
	}
	delta := file.size - file.bytes
	if delta > 0 {
		file.bytes = file.size
		p.totalDone += delta
		if p.totalDone > p.totalBytes {
			p.totalDone = p.totalBytes
		}
	}
	file.completed = true
	return p.snapshot(index), started, true
}

func (c *Client) ensureEventDispatcher() *eventDispatcher {
	if c.Options.EventSink == nil {
		return nil
	}
	c.eventMu.Lock()
	defer c.eventMu.Unlock()
	if c.events == nil {
		c.events = newEventDispatcher(c.Options.EventSink)
	}
	return c.events
}

func (c *Client) emitTransferEvent(event TransferEvent) {
	if dispatcher := c.ensureEventDispatcher(); dispatcher != nil {
		dispatcher.enqueue(event)
	}
}

func (c *Client) emitPhase(phase TransferPhase) {
	c.emitTransferEvent(TransferEvent{Type: TransferEventPhase, Phase: phase})
}

func (c *Client) emitManifestReady(manifest ReceiveManifest) {
	snapshot := cloneReceiveManifest(manifest)
	c.emitTransferEvent(TransferEvent{Type: TransferEventManifestReady, Manifest: &snapshot})
}

func (c *Client) emitReconnect(attempt int) {
	c.emitTransferEvent(TransferEvent{
		Type:             TransferEventReconnect,
		Phase:            TransferPhaseReconnecting,
		ReconnectAttempt: attempt,
	})
}

func progressEvent(eventType TransferEventType, snapshot progressSnapshot) TransferEvent {
	return TransferEvent{
		Type:                  eventType,
		FileIndex:             snapshot.fileIndex,
		FilePath:              snapshot.filePath,
		FileSize:              snapshot.fileSize,
		FileBytesTransferred:  snapshot.fileBytes,
		TotalBytesTransferred: snapshot.totalDone,
		TotalBytes:            snapshot.totalSize,
	}
}

func (c *Client) initializeTransferProgress(files []FileInfo) {
	if c.Options.EventSink == nil {
		return
	}
	c.progressMu.Lock()
	c.progress = newProgressTracker(files)
	c.progressMu.Unlock()
}

func (c *Client) currentProgressTracker() *progressTracker {
	c.progressMu.Lock()
	defer c.progressMu.Unlock()
	return c.progress
}

func (c *Client) startTransferFileProgress(index int, missingPositions []int64) {
	tracker := c.currentProgressTracker()
	if tracker == nil {
		return
	}
	snapshot, started, changed := tracker.start(index, missingPositions)
	if started {
		c.emitTransferEvent(progressEvent(TransferEventFileStarted, snapshot))
	}
	if started || changed {
		c.emitTransferEvent(progressEvent(TransferEventProgress, snapshot))
	}
}

func (c *Client) addTransferFileProgress(index int, position int64, count int) {
	tracker := c.currentProgressTracker()
	if tracker == nil {
		return
	}
	snapshot, started, changed := tracker.add(index, position, count)
	if started {
		c.emitTransferEvent(progressEvent(TransferEventFileStarted, snapshot))
	}
	if changed {
		c.emitTransferEvent(progressEvent(TransferEventProgress, snapshot))
	}
}

func (c *Client) completeTransferFileProgress(index int) {
	tracker := c.currentProgressTracker()
	if tracker == nil {
		return
	}
	snapshot, started, completed := tracker.complete(index)
	if started {
		c.emitTransferEvent(progressEvent(TransferEventFileStarted, snapshot))
	}
	if !completed {
		return
	}
	c.emitTransferEvent(progressEvent(TransferEventProgress, snapshot))
	c.emitTransferEvent(progressEvent(TransferEventFileCompleted, snapshot))
}

func (c *Client) completeAllTransferProgress() {
	tracker := c.currentProgressTracker()
	if tracker == nil {
		return
	}
	tracker.mu.Lock()
	count := len(tracker.files)
	tracker.mu.Unlock()
	for index := 0; index < count; index++ {
		c.completeTransferFileProgress(index)
	}
}

func terminalStateFor(err error, successful bool) TransferTerminalState {
	if err == nil && successful {
		return TransferTerminalCompleted
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return TransferTerminalCanceled
	}
	if err != nil && (strings.Contains(err.Error(), "refused files") || strings.Contains(err.Error(), "refusing files")) {
		return TransferTerminalRejected
	}
	return TransferTerminalFailed
}

func (c *Client) finishTransferEvents(err error) {
	if c.Options.EventSink == nil {
		return
	}
	c.eventTerminalOnce.Do(func() {
		state := terminalStateFor(err, c.SuccessfulTransfer)
		if state == TransferTerminalCompleted {
			c.completeAllTransferProgress()
		}
		c.emitPhase(TransferPhaseFinalizing)
		c.emitTransferEvent(TransferEvent{Type: TransferEventTerminal, TerminalState: state})
	})
}

// WaitForEventDrain waits until the terminal event has been delivered and the
// per-client dispatcher has exited. Callers should use a cleanup context that
// is independent from the transfer context.
func (c *Client) WaitForEventDrain(ctx context.Context) error {
	c.eventMu.Lock()
	dispatcher := c.events
	c.eventMu.Unlock()
	if dispatcher == nil {
		return nil
	}
	return dispatcher.wait(ctx)
}
