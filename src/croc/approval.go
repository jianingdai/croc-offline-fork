package croc

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/denisbrodbeck/machineid"

	"github.com/schollz/croc/v10/src/termui"
	"github.com/schollz/croc/v10/src/utils"
)

// ManifestDecision is the receiver's decision for an incoming manifest.
type ManifestDecision uint8

const (
	// ManifestReject refuses the incoming manifest.
	ManifestReject ManifestDecision = iota
	// ManifestAccept accepts the incoming manifest.
	ManifestAccept
)

// ManifestApprover decides whether an incoming, validated manifest is accepted.
type ManifestApprover interface {
	Approve(context.Context, ReceiveManifest) (ManifestDecision, error)
}

// ManifestApproverFunc adapts a function to ManifestApprover.
type ManifestApproverFunc func(context.Context, ReceiveManifest) (ManifestDecision, error)

// Approve calls f(ctx, manifest).
func (f ManifestApproverFunc) Approve(ctx context.Context, manifest ReceiveManifest) (ManifestDecision, error) {
	return f(ctx, manifest)
}

// ManifestEntryType identifies the kind of an incoming manifest entry.
type ManifestEntryType string

const (
	// ManifestEntryFile is a regular file.
	ManifestEntryFile ManifestEntryType = "file"
	// ManifestEntryDirectory is an empty directory explicitly sent by the peer.
	ManifestEntryDirectory ManifestEntryType = "directory"
	// ManifestEntrySymlink is a symbolic link.
	ManifestEntrySymlink ManifestEntryType = "symlink"
)

// ReceiveManifestEntry is a safe snapshot of one validated incoming path.
type ReceiveManifestEntry struct {
	Path       string
	Type       ManifestEntryType
	Size       int64
	Mode       os.FileMode
	ModTime    time.Time
	LinkTarget string
}

// ReceiveManifest is a safe snapshot of validated incoming metadata.
// It deliberately excludes hashes, source paths, machine IDs, and protocol
// identifiers.
type ReceiveManifest struct {
	Entries        []ReceiveManifestEntry
	Count          int
	FileCount      int
	DirectoryCount int
	TotalBytes     int64
}

type manifestApprovalResult struct {
	decision ManifestDecision
	err      error
}

func cloneReceiveManifest(manifest ReceiveManifest) ReceiveManifest {
	cloned := manifest
	cloned.Entries = append([]ReceiveManifestEntry(nil), manifest.Entries...)
	return cloned
}

func newReceiveManifest(files, emptyFolders []FileInfo, totalBytes int64) ReceiveManifest {
	manifest := ReceiveManifest{
		Entries:        make([]ReceiveManifestEntry, 0, len(files)+len(emptyFolders)),
		Count:          len(files) + len(emptyFolders),
		FileCount:      len(files),
		DirectoryCount: len(emptyFolders),
		TotalBytes:     totalBytes,
	}
	for _, file := range files {
		entryType := ManifestEntryFile
		if file.Symlink != "" {
			entryType = ManifestEntrySymlink
		}
		manifest.Entries = append(manifest.Entries, ReceiveManifestEntry{
			Path:       path.Clean(path.Join(file.FolderRemote, file.Name)),
			Type:       entryType,
			Size:       file.Size,
			Mode:       file.Mode.Perm(),
			ModTime:    file.ModTime,
			LinkTarget: file.Symlink,
		})
	}
	for _, folder := range emptyFolders {
		manifest.Entries = append(manifest.Entries, ReceiveManifestEntry{
			Path:    path.Clean(folder.FolderRemote),
			Type:    ManifestEntryDirectory,
			Size:    folder.Size,
			Mode:    folder.Mode.Perm(),
			ModTime: folder.ModTime,
		})
	}
	return manifest
}

// awaitManifestDecision defines the approval linearization point. Cancellation
// is checked before waiting and again after receiving a result, so an already
// observable cancellation always wins over an Accept result.
func awaitManifestDecision(ctx context.Context, results <-chan manifestApprovalResult) (ManifestDecision, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ManifestReject, err
	}
	select {
	case <-ctx.Done():
		return ManifestReject, ctx.Err()
	default:
	}

	select {
	case <-ctx.Done():
		return ManifestReject, ctx.Err()
	case result, ok := <-results:
		if err := ctx.Err(); err != nil {
			return ManifestReject, err
		}
		if !ok {
			return ManifestReject, fmt.Errorf("manifest approver returned no decision")
		}
		if result.err != nil {
			return ManifestReject, result.err
		}
		if result.decision != ManifestAccept && result.decision != ManifestReject {
			return ManifestReject, fmt.Errorf("invalid manifest decision %d", result.decision)
		}
		return result.decision, nil
	}
}

func (c *Client) approveReceiveManifest(manifest ReceiveManifest) (ManifestDecision, error) {
	if c.Options.ManifestApprover == nil {
		return ManifestAccept, nil
	}
	ctx := c.stop.ctx
	results := make(chan manifestApprovalResult, 1)
	approver := c.Options.ManifestApprover
	go func() {
		decision, err := approver.Approve(ctx, cloneReceiveManifest(manifest))
		results <- manifestApprovalResult{decision: decision, err: err}
	}()
	return awaitManifestDecision(ctx, results)
}

func (c *Client) promptForManifestApproval(senderInfo SenderInfo, totalSize int64) (ManifestDecision, error) {
	fname := fmt.Sprintf("%d files", len(c.FilesToTransfer))
	folderName := fmt.Sprintf("%d folders", c.TotalNumberFolders)
	displayName := ""
	if len(c.FilesToTransfer) == 1 {
		displayName = c.FilesToTransfer[0].Name
		fname = quotedFilename(displayName, false)
	}

	action := "Accept"
	if c.Options.SendingText {
		action = "Display"
		fname = "text message"
		displayName = ""
	}
	if !c.Options.NoPrompt || c.Options.Ask || senderInfo.Ask {
		output, colorEnabled := termui.Output(os.Stderr)
		if displayName != "" {
			fname = quotedFilename(displayName, colorEnabled)
		}
		choicePrompt := termui.Emphasis("(Y/n)", colorEnabled)
		if c.Options.Ask || senderInfo.Ask {
			machID, _ := machineid.ID()
			fmt.Fprintf(output, "\rYour machine id is '%s'.\n%s %s (%s) from '%s'? %s ", machID, action, fname, utils.ByteCountDecimal(totalSize), senderInfo.MachineID, choicePrompt)
		} else if c.TotalNumberFolders > 0 {
			fmt.Fprintf(output, "\r%s %s and %s (%s)? %s ", action, fname, folderName, utils.ByteCountDecimal(totalSize), choicePrompt)
		} else {
			fmt.Fprintf(output, "\r%s %s (%s)? %s ", action, fname, utils.ByteCountDecimal(totalSize), choicePrompt)
		}
		choice, err := utils.GetInput("")
		choice = strings.ToLower(choice)
		if err != nil || (choice != "" && choice != "y" && choice != "yes") {
			return ManifestReject, nil
		}
		return ManifestAccept, nil
	}

	c.printReceiveManifestSummary(totalSize)
	return ManifestAccept, nil
}

func (c *Client) printReceiveManifestSummary(totalSize int64) {
	fname := fmt.Sprintf("%d files", len(c.FilesToTransfer))
	displayName := ""
	if len(c.FilesToTransfer) == 1 {
		displayName = c.FilesToTransfer[0].Name
	}
	if c.Options.SendingText {
		fname = "text message"
		displayName = ""
	}
	output, colorEnabled := termui.Output(os.Stderr)
	if displayName != "" {
		fname = quotedFilename(displayName, colorEnabled)
	}
	fmt.Fprintf(output, "\rReceiving %s (%s) \n", fname, utils.ByteCountDecimal(totalSize))
}
