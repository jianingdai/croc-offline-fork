package integrationtest

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/schollz/croc/v10/src/croc"
	"github.com/schollz/croc/v10/src/tcp"
)

type cancellationObserver struct {
	mu           sync.Mutex
	events       []croc.TransferEvent
	progress     chan struct{}
	reconnect    chan struct{}
	progressOne  sync.Once
	reconnectOne sync.Once
	onReconnect  func()
}

func newCancellationObserver() *cancellationObserver {
	return &cancellationObserver{
		progress:  make(chan struct{}),
		reconnect: make(chan struct{}),
	}
}

func (o *cancellationObserver) sink(event croc.TransferEvent) {
	o.mu.Lock()
	o.events = append(o.events, event)
	o.mu.Unlock()
	if event.Type == croc.TransferEventProgress && event.TotalBytesTransferred > 0 {
		o.progressOne.Do(func() { close(o.progress) })
	}
	if event.Type == croc.TransferEventReconnect {
		o.reconnectOne.Do(func() {
			close(o.reconnect)
			if o.onReconnect != nil {
				o.onReconnect()
			}
		})
	}
}

func (o *cancellationObserver) terminalStates() []croc.TransferTerminalState {
	o.mu.Lock()
	defer o.mu.Unlock()
	states := make([]croc.TransferTerminalState, 0, 1)
	for _, event := range o.events {
		if event.Type == croc.TransferEventTerminal {
			states = append(states, event.TerminalState)
		}
	}
	return states
}

func procFDCount() int {
	if runtime.GOOS != "linux" {
		return -1
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

func waitForFDIncrease(t *testing.T, baseline int) {
	t.Helper()
	if baseline < 0 {
		time.Sleep(100 * time.Millisecond)
		return
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if procFDCount() >= baseline+2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("transfer did not establish its loopback socket")
}

func assertResourcesReturn(t *testing.T, fdBaseline, goroutineBaseline int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		fdOK := fdBaseline < 0 || procFDCount() <= fdBaseline+1
		goroutineOK := runtime.NumGoroutine() <= goroutineBaseline+6
		if fdOK && goroutineOK {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("resources did not settle: fd baseline=%d current=%d goroutine baseline=%d current=%d",
		fdBaseline, procFDCount(), goroutineBaseline, runtime.NumGoroutine())
}

func waitForResult(t *testing.T, result <-chan error, timeout time.Duration) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(timeout):
		t.Fatal("canceled transfer did not return")
		return nil
	}
}

func assertCanceledDrain(t *testing.T, client *croc.Client, observer *cancellationObserver) {
	t.Helper()
	drainCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.WaitForEventDrain(drainCtx); err != nil {
		t.Fatalf("drain canceled terminal event: %v", err)
	}
	states := observer.terminalStates()
	if len(states) != 1 || states[0] != croc.TransferTerminalCanceled {
		t.Fatalf("terminal states after cancellation: %v", states)
	}
}

func assertNoOpenFileDescriptor(t *testing.T, fileName string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		return
	}
	want, err := filepath.EvalSymlinks(fileName)
	if err != nil {
		want = fileName
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read process descriptors: %v", err)
	}
	for _, entry := range entries {
		target, readErr := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if readErr == nil && target == want {
			t.Fatalf("file descriptor remained open for %s", filepath.Base(fileName))
		}
	}
}

func assertNoStagingFiles(t *testing.T, receiveDir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(receiveDir, ".croc-staging-*"))
	if err != nil {
		t.Fatalf("scan staging paths: %v", err)
	}
	if len(matches) != 0 {
		t.Fatal("croc created a staging path during cancellation")
	}
}

func createLargeCancellationFixture(t *testing.T) (string, string, []croc.FileInfo, []croc.FileInfo, int) {
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
	sourcePath := filepath.Join(sourceDir, "cancellation-payload.bin")
	if err := os.WriteFile(sourcePath, bytes.Repeat([]byte{0x5a}, 8*1024*1024), 0o640); err != nil {
		t.Fatalf("create cancellation fixture: %v", err)
	}
	files, folders, folderCount, err := croc.GetFilesInfo([]string{sourcePath}, false, false, nil)
	if err != nil {
		t.Fatalf("collect cancellation fixture: %v", err)
	}
	return sourcePath, receiveDir, files, folders, folderCount
}

func TestCancellationWaitingPeerResourceLifecycle(t *testing.T) {
	relay := startLoopbackRelay(t)
	sourcePath, _, files, folders, folderCount := createTransferFixture(t)
	observer := newCancellationObserver()
	ctx, cancel := context.WithCancel(context.Background())
	options := transferOptions(relay, testSecret(t))
	options.IsSender = true
	options.EventSink = croc.EventSinkFunc(observer.sink)
	sender, err := croc.NewCtx(ctx, options)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	fdBaseline := procFDCount()
	goroutineBaseline := runtime.NumGoroutine()
	result := make(chan error, 1)
	go func() { result <- sender.Send(files, folders, folderCount) }()
	waitForFDIncrease(t, fdBaseline)

	started := time.Now()
	cancel()
	if err := waitForResult(t, result, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("waiting-peer cancellation was not identifiable")
	}
	if time.Since(started) > time.Second {
		t.Fatal("waiting-peer cancellation exceeded one second")
	}
	assertCanceledDrain(t, sender, observer)
	assertNoOpenFileDescriptor(t, sourcePath)
	assertResourcesReturn(t, fdBaseline, goroutineBaseline)
}

func TestCancellationSecuringClosesFakePeer(t *testing.T) {
	relay := startLoopbackRelay(t)
	_, _, files, folders, folderCount := createTransferFixture(t)
	observer := newCancellationObserver()
	ctx, cancel := context.WithCancel(context.Background())
	options := transferOptions(relay, testSecret(t))
	options.IsSender = true
	options.EventSink = croc.EventSinkFunc(observer.sink)
	sender, err := croc.NewCtx(ctx, options)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	fdBaseline := procFDCount()
	goroutineBaseline := runtime.NumGoroutine()
	result := make(chan error, 1)
	go func() { result <- sender.Send(files, folders, folderCount) }()

	fakePeer, _, _, err := tcp.ConnectToTCPServerContext(context.Background(), relay.address, relay.password, sender.Options.RoomName)
	if err != nil {
		cancel()
		t.Fatalf("connect fake peer: %v", err)
	}
	defer fakePeer.Close()
	if err := fakePeer.Send([]byte("handshake")); err != nil {
		cancel()
		t.Fatalf("send fake peer handshake: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	securingObserved := false
	for time.Now().Before(deadline) {
		observer.mu.Lock()
		securing := false
		for _, event := range observer.events {
			if event.Type == croc.TransferEventPhase && event.Phase == croc.TransferPhaseSecuring {
				securing = true
				break
			}
		}
		observer.mu.Unlock()
		if securing {
			securingObserved = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !securingObserved {
		cancel()
		t.Fatal("sender did not enter securing phase")
	}

	started := time.Now()
	cancel()
	if err := waitForResult(t, result, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("securing cancellation was not identifiable")
	}
	if time.Since(started) > time.Second {
		t.Fatal("securing cancellation exceeded one second")
	}
	if err := fakePeer.Connection().SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set fake peer deadline: %v", err)
	}
	for {
		if _, err := fakePeer.Receive(); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Fatal("fake peer did not observe control socket closure")
			}
			break
		}
	}
	assertCanceledDrain(t, sender, observer)
	fakePeer.Close()
	assertResourcesReturn(t, fdBaseline, goroutineBaseline)
}

func TestCancellationAwaitingApprovalResourceLifecycle(t *testing.T) {
	relay := startLoopbackRelay(t)
	sourcePath, receiveDir, files, folders, folderCount := createTransferFixture(t)
	changeWorkingDirectory(t, receiveDir)
	receiverObserver := newCancellationObserver()
	approverEntered := make(chan struct{})
	approver := croc.ManifestApproverFunc(func(ctx context.Context, _ croc.ReceiveManifest) (croc.ManifestDecision, error) {
		close(approverEntered)
		<-ctx.Done()
		return croc.ManifestReject, ctx.Err()
	})
	senderCtx, cancelSender := context.WithCancel(context.Background())
	defer cancelSender()
	receiverCtx, cancelReceiver := context.WithCancel(context.Background())
	sender, receiver := newTransferClients(t, relay, testSecret(t), senderCtx, receiverCtx, approver)
	receiver.Options.EventSink = croc.EventSinkFunc(receiverObserver.sink)
	fdBaseline := procFDCount()
	goroutineBaseline := runtime.NumGoroutine()
	senderResult := make(chan error, 1)
	receiverResult := make(chan error, 1)
	go func() { senderResult <- sender.Send(files, folders, folderCount) }()
	go func() { receiverResult <- receiver.Receive() }()
	select {
	case <-approverEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("receiver did not reach approval")
	}

	started := time.Now()
	cancelReceiver()
	if err := waitForResult(t, receiverResult, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("approval cancellation was not identifiable")
	}
	if time.Since(started) > time.Second {
		t.Fatal("approval cancellation exceeded one second")
	}
	if err := waitForResult(t, senderResult, time.Second); err == nil {
		t.Fatal("sender did not observe approval-side connection closure")
	}
	assertCanceledDrain(t, receiver, receiverObserver)
	targetPath := filepath.Join(receiveDir, filepath.Base(sourcePath))
	if _, err := os.Lstat(targetPath); !os.IsNotExist(err) {
		t.Fatal("approval cancellation created a target file")
	}
	assertNoStagingFiles(t, receiveDir)
	assertResourcesReturn(t, fdBaseline, goroutineBaseline)
}

func TestCancellationTransferringResourceLifecycle(t *testing.T) {
	relay := startLoopbackRelayWithDataPorts(t, 2)
	sourcePath, receiveDir, files, folders, folderCount := createLargeCancellationFixture(t)
	changeWorkingDirectory(t, receiveDir)
	senderObserver := newCancellationObserver()
	receiverObserver := newCancellationObserver()
	senderCtx, cancelSender := context.WithCancel(context.Background())
	receiverCtx, cancelReceiver := context.WithCancel(context.Background())
	approver := croc.ManifestApproverFunc(func(_ context.Context, _ croc.ReceiveManifest) (croc.ManifestDecision, error) {
		return croc.ManifestAccept, nil
	})
	common := transferOptions(relay, testSecret(t))
	common.NoMultiplexing = false
	senderOptions := common
	senderOptions.IsSender = true
	senderOptions.ThrottleUpload = "128k"
	senderOptions.EventSink = croc.EventSinkFunc(senderObserver.sink)
	sender, err := croc.NewCtx(senderCtx, senderOptions)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	receiverOptions := common
	receiverOptions.ManifestApprover = approver
	receiverOptions.EventSink = croc.EventSinkFunc(receiverObserver.sink)
	receiver, err := croc.NewCtx(receiverCtx, receiverOptions)
	if err != nil {
		t.Fatalf("create receiver: %v", err)
	}
	fdBaseline := procFDCount()
	goroutineBaseline := runtime.NumGoroutine()
	senderResult := make(chan error, 1)
	receiverResult := make(chan error, 1)
	go func() { senderResult <- sender.Send(files, folders, folderCount) }()
	go func() { receiverResult <- receiver.Receive() }()
	select {
	case <-receiverObserver.progress:
	case <-time.After(5 * time.Second):
		t.Fatal("transfer did not produce progress before cancellation")
	}

	started := time.Now()
	cancelSender()
	cancelReceiver()
	if err := waitForResult(t, senderResult, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("sender transfer cancellation was not identifiable")
	}
	if err := waitForResult(t, receiverResult, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("receiver transfer cancellation was not identifiable")
	}
	if time.Since(started) > time.Second {
		t.Fatal("transfer cancellation exceeded one second")
	}
	assertCanceledDrain(t, sender, senderObserver)
	assertCanceledDrain(t, receiver, receiverObserver)
	if sender.SuccessfulTransfer || receiver.SuccessfulTransfer {
		t.Fatal("partial transfer was reported as successful")
	}
	targetPath := filepath.Join(receiveDir, filepath.Base(sourcePath))
	assertNoOpenFileDescriptor(t, sourcePath)
	assertNoOpenFileDescriptor(t, targetPath)
	if err := os.Rename(sourcePath, sourcePath+".renamed"); err != nil {
		t.Fatalf("source file handle remained open: %v", err)
	}
	if err := os.Rename(targetPath, targetPath+".renamed"); err != nil {
		t.Fatalf("target file handle remained open: %v", err)
	}
	assertNoStagingFiles(t, receiveDir)
	assertResourcesReturn(t, fdBaseline, goroutineBaseline)
}

func TestCancellationReconnectBackoffResourceLifecycle(t *testing.T) {
	relay := startLoopbackRelay(t)
	sourcePath, receiveDir, files, folders, folderCount := createLargeCancellationFixture(t)
	changeWorkingDirectory(t, receiveDir)
	senderCtx, cancelSender := context.WithCancel(context.Background())
	receiverCtx, cancelReceiver := context.WithCancel(context.Background())
	defer cancelSender()
	defer cancelReceiver()
	cancelBoth := func() {
		cancelSender()
		cancelReceiver()
	}
	senderObserver := newCancellationObserver()
	receiverObserver := newCancellationObserver()
	var cancelOnce sync.Once
	senderObserver.onReconnect = func() { cancelOnce.Do(cancelBoth) }
	receiverObserver.onReconnect = func() { cancelOnce.Do(cancelBoth) }
	approver := croc.ManifestApproverFunc(func(_ context.Context, _ croc.ReceiveManifest) (croc.ManifestDecision, error) {
		return croc.ManifestAccept, nil
	})
	common := transferOptions(relay, testSecret(t))
	senderOptions := common
	senderOptions.IsSender = true
	senderOptions.ThrottleUpload = "128k"
	senderOptions.EventSink = croc.EventSinkFunc(senderObserver.sink)
	sender, err := croc.NewCtx(senderCtx, senderOptions)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	receiverOptions := common
	receiverOptions.ManifestApprover = approver
	receiverOptions.EventSink = croc.EventSinkFunc(receiverObserver.sink)
	receiver, err := croc.NewCtx(receiverCtx, receiverOptions)
	if err != nil {
		t.Fatalf("create receiver: %v", err)
	}
	fdBaseline := procFDCount()
	goroutineBaseline := runtime.NumGoroutine()
	senderResult := make(chan error, 1)
	receiverResult := make(chan error, 1)
	go func() { senderResult <- sender.Send(files, folders, folderCount) }()
	go func() { receiverResult <- receiver.Receive() }()
	select {
	case <-receiverObserver.progress:
	case <-time.After(5 * time.Second):
		t.Fatal("transfer did not begin before relay shutdown")
	}

	relay.stop()
	select {
	case <-senderObserver.reconnect:
	case <-receiverObserver.reconnect:
	case <-time.After(2 * time.Second):
		t.Fatal("transfer did not enter reconnect/backoff")
	}
	started := time.Now()
	if err := waitForResult(t, senderResult, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("sender reconnect cancellation was not identifiable")
	}
	if err := waitForResult(t, receiverResult, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("receiver reconnect cancellation was not identifiable")
	}
	if time.Since(started) > time.Second {
		t.Fatal("reconnect cancellation exceeded one second")
	}
	assertCanceledDrain(t, sender, senderObserver)
	assertCanceledDrain(t, receiver, receiverObserver)
	if sender.SuccessfulTransfer || receiver.SuccessfulTransfer {
		t.Fatal("interrupted reconnect was reported as successful")
	}
	assertNoOpenFileDescriptor(t, sourcePath)
	assertNoOpenFileDescriptor(t, filepath.Join(receiveDir, filepath.Base(sourcePath)))
	assertNoStagingFiles(t, receiveDir)
	assertResourcesReturn(t, fdBaseline, goroutineBaseline)
}
