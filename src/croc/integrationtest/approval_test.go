package integrationtest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/schollz/croc/v10/src/croc"
)

func TestManifestApprovalAccept(t *testing.T) {
	relay := startLoopbackRelay(t)
	sourcePath, receiveDir, files, folders, folderCount := createTransferFixture(t)
	changeWorkingDirectory(t, receiveDir)

	manifestSeen := make(chan croc.ReceiveManifest, 1)
	approver := croc.ManifestApproverFunc(func(_ context.Context, manifest croc.ReceiveManifest) (croc.ManifestDecision, error) {
		manifestSeen <- manifest
		return croc.ManifestAccept, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sender, receiver := newTransferClients(t, relay, testSecret(t), ctx, ctx, approver)

	senderErr, receiverErr := runTransferPair(t, sender, receiver, files, folders, folderCount)
	if senderErr != nil || receiverErr != nil {
		t.Fatalf("accepted transfer failed: sender=%v receiver=%v", senderErr, receiverErr)
	}
	manifest := <-manifestSeen
	if manifest.Count != 1 || manifest.FileCount != 1 || manifest.TotalBytes != int64(len("test-only-approval-payload")) {
		t.Fatal("approver did not receive the complete manifest")
	}
	if len(manifest.Entries) != 1 || manifest.Entries[0].Path != filepath.Base(sourcePath) {
		t.Fatal("approver received an unexpected normalized path")
	}
	want, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(receiveDir, filepath.Base(sourcePath)))
	if err != nil {
		t.Fatalf("read received file: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("accepted transfer payload differs")
	}
}

func TestManifestApprovalRejectUsesExistingProtocolError(t *testing.T) {
	relay := startLoopbackRelay(t)
	sourcePath, receiveDir, files, folders, folderCount := createTransferFixture(t)
	changeWorkingDirectory(t, receiveDir)
	approver := croc.ManifestApproverFunc(func(_ context.Context, _ croc.ReceiveManifest) (croc.ManifestDecision, error) {
		return croc.ManifestReject, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sender, receiver := newTransferClients(t, relay, testSecret(t), ctx, ctx, approver)

	senderErr, receiverErr := runTransferPair(t, sender, receiver, files, folders, folderCount)
	if senderErr == nil || !strings.Contains(senderErr.Error(), "refusing files") {
		t.Fatal("sender did not receive the existing refusing-files protocol error")
	}
	if receiverErr == nil || !strings.Contains(receiverErr.Error(), "refused files") {
		t.Fatal("receiver did not report manifest rejection")
	}
	if _, err := os.Lstat(filepath.Join(receiveDir, filepath.Base(sourcePath))); !os.IsNotExist(err) {
		t.Fatal("rejected manifest created a destination file")
	}
	if receiver.SuccessfulTransfer {
		t.Fatal("rejected manifest was reported as successful")
	}
}

func TestApprovalCancelWinsAcceptLoopback(t *testing.T) {
	relay := startLoopbackRelay(t)
	sourcePath, receiveDir, files, folders, folderCount := createTransferFixture(t)
	changeWorkingDirectory(t, receiveDir)
	senderCtx, cancelSender := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelSender()
	receiverCtx, cancelReceiver := context.WithCancel(context.Background())
	defer cancelReceiver()
	approverEntered := make(chan struct{})
	release := make(chan struct{})
	approver := croc.ManifestApproverFunc(func(ctx context.Context, _ croc.ReceiveManifest) (croc.ManifestDecision, error) {
		close(approverEntered)
		<-release
		cancelReceiver()
		<-ctx.Done()
		return croc.ManifestAccept, nil
	})
	sender, receiver := newTransferClients(t, relay, testSecret(t), senderCtx, receiverCtx, approver)

	senderResult := make(chan error, 1)
	receiverResult := make(chan error, 1)
	go func() { senderResult <- sender.Send(files, folders, folderCount) }()
	go func() { receiverResult <- receiver.Receive() }()
	select {
	case <-approverEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("receiver did not reach manifest approval")
	}
	close(release)

	select {
	case err := <-receiverResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("receiver cancellation did not win over Accept")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("receiver did not return after approval cancellation")
	}
	select {
	case <-senderResult:
	case <-time.After(3 * time.Second):
		cancelSender()
		t.Fatal("sender did not exit after receiver canceled approval")
	}
	if _, err := os.Lstat(filepath.Join(receiveDir, filepath.Base(sourcePath))); !os.IsNotExist(err) {
		t.Fatal("canceled approval created a destination file")
	}
	if receiver.SuccessfulTransfer {
		t.Fatal("canceled approval was reported as successful")
	}
}
