package croc

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/schollz/croc/v10/src/message"
)

func TestReceiveManifestSnapshotUsesSafeNormalizedFields(t *testing.T) {
	modTime := time.Unix(1_700_000_000, 123)
	files, folders, err := validateReceiveMetadata([]FileInfo{
		{
			Name:         "payload.txt",
			FolderRemote: `nested\folder`,
			FolderSource: "/test-only/source",
			Hash:         []byte("test-only-hash"),
			Size:         12,
			Mode:         os.ModeSymlink | 0o777,
			ModTime:      modTime,
			Symlink:      "../target.txt",
		},
	}, []FileInfo{
		{
			FolderRemote: "empty/./folder",
			Mode:         os.ModeDir | 0o750,
			ModTime:      modTime,
		},
	})
	if err != nil {
		t.Fatalf("validate manifest: %v", err)
	}

	manifest := newReceiveManifest(files, folders, 12)
	if manifest.Count != 2 || manifest.FileCount != 1 || manifest.DirectoryCount != 1 || manifest.TotalBytes != 12 {
		t.Fatal("manifest summary does not match validated metadata")
	}
	wantEntries := []ReceiveManifestEntry{
		{
			Path:       "nested/folder/payload.txt",
			Type:       ManifestEntrySymlink,
			Size:       12,
			Mode:       0o777,
			ModTime:    modTime,
			LinkTarget: "../target.txt",
		},
		{
			Path:    "empty/folder",
			Type:    ManifestEntryDirectory,
			Mode:    0o750,
			ModTime: modTime,
		},
	}
	if !reflect.DeepEqual(manifest.Entries, wantEntries) {
		t.Fatal("manifest entries do not match the safe normalized snapshot")
	}

	assertPublicFields := func(value any, want []string) {
		t.Helper()
		typeOf := reflect.TypeOf(value)
		got := make([]string, typeOf.NumField())
		for i := range got {
			got[i] = typeOf.Field(i).Name
		}
		if !slices.Equal(got, want) {
			t.Fatalf("unexpected public manifest fields: %v", got)
		}
	}
	assertPublicFields(ReceiveManifest{}, []string{"Entries", "Count", "FileCount", "DirectoryCount", "TotalBytes"})
	assertPublicFields(ReceiveManifestEntry{}, []string{"Path", "Type", "Size", "Mode", "ModTime", "LinkTarget"})
}

func TestManifestApprovalSnapshotCannotMutateClientMetadata(t *testing.T) {
	ctx := context.Background()
	var callbackCalled bool
	client := &Client{
		Options: Options{
			Ask: true,
			ManifestApprover: ManifestApproverFunc(func(_ context.Context, manifest ReceiveManifest) (ManifestDecision, error) {
				callbackCalled = true
				manifest.Entries[0].Path = "mutated.txt"
				manifest.Entries = nil
				return ManifestAccept, nil
			}),
		},
		FilesHasFinished: make(map[int]struct{}),
		stop:             newStop(ctx),
	}
	senderInfo := SenderInfo{
		FilesToTransfer: []FileInfo{{
			Name:         "payload.txt",
			FolderRemote: "nested/./folder",
			FolderSource: "/test-only/source",
			Hash:         []byte("test-only-hash"),
			Size:         7,
			Mode:         0o640,
		}},
		Ask: true,
	}
	payload, err := jsonMarshal(senderInfo)
	if err != nil {
		t.Fatalf("marshal sender info: %v", err)
	}

	done, err := client.processMessageFileInfo(message.Message{Type: message.TypeFileInfo, Bytes: payload})
	if err != nil || done {
		t.Fatalf("process accepted manifest: done=%t err=%v", done, err)
	}
	if !callbackCalled {
		t.Fatal("manifest approver was not called")
	}
	if len(client.FilesToTransfer) != 1 || client.FilesToTransfer[0].FolderRemote != "nested/folder" || client.FilesToTransfer[0].Name != "payload.txt" {
		t.Fatal("approver mutation changed internal file metadata")
	}
	if string(client.FilesToTransfer[0].Hash) != "test-only-hash" {
		t.Fatal("internal hash changed while presenting safe manifest")
	}
}

func TestManifestValidationRejectsInvalidSizes(t *testing.T) {
	tests := []struct {
		name    string
		files   []FileInfo
		folders []FileInfo
	}{
		{
			name:  "negative file",
			files: []FileInfo{{Name: "negative.txt", FolderRemote: ".", Size: -1}},
		},
		{
			name:    "negative folder",
			folders: []FileInfo{{FolderRemote: "negative-folder", Size: -1}},
		},
		{
			name: "total overflow",
			files: []FileInfo{
				{Name: "large.bin", FolderRemote: ".", Size: math.MaxInt64},
				{Name: "overflow.bin", FolderRemote: ".", Size: 1},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := validateReceiveMetadata(test.files, test.folders); err == nil {
				t.Fatal("invalid manifest size was accepted")
			}
		})
	}
}

func TestCancelWinsAcceptWhenBothReady(t *testing.T) {
	for i := 0; i < 1_000; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		results := make(chan manifestApprovalResult, 1)
		results <- manifestApprovalResult{decision: ManifestAccept}

		decision, err := awaitManifestDecision(ctx, results)
		if decision != ManifestReject || !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d did not deterministically prefer cancellation", i)
		}
	}
}

func TestApprovalCancelWinsAcceptAfterBarrier(t *testing.T) {
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		results := make(chan manifestApprovalResult, 1)
		release := make(chan struct{})
		canceled := make(chan struct{})

		go func() {
			<-release
			cancel()
			<-ctx.Done()
			close(canceled)
		}()
		go func() {
			<-release
			<-canceled
			results <- manifestApprovalResult{decision: ManifestAccept}
		}()
		close(release)
		<-canceled

		decision, err := awaitManifestDecision(ctx, results)
		if decision != ManifestReject || !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d accepted after cancellation became observable", i)
		}
	}
}

func TestManifestApprovalCallbackCancelWinsAccept(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{
		Options: Options{
			ManifestApprover: ManifestApproverFunc(func(callbackCtx context.Context, _ ReceiveManifest) (ManifestDecision, error) {
				cancel()
				<-callbackCtx.Done()
				return ManifestAccept, nil
			}),
		},
		stop: newStop(ctx),
	}

	decision, err := client.approveReceiveManifest(ReceiveManifest{})
	if decision != ManifestReject || !errors.Is(err, context.Canceled) {
		t.Fatal("callback Accept won after cancellation was observable")
	}
}

// jsonMarshal keeps test failures from formatting the complete metadata value.
func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}
