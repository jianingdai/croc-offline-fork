// ctx.go
package utils

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/minio/highwayhash"
	"github.com/schollz/progressbar/v3"
)

// WaitContext waits for duration or returns early when ctx is canceled.
func WaitContext(ctx context.Context, duration time.Duration) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ctxFile wraps os.File with context cancellation support.
type ctxFile struct {
	ctx context.Context
	f   *os.File
}

// NewCtxFile creates a new context-aware file wrapper.
func NewCtxFile(ctx context.Context, f *os.File) *ctxFile {
	return &ctxFile{ctx: ctx, f: f}
}

// Read implements io.Reader interface with context cancellation.
func (c *ctxFile) Read(p []byte) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
		n, err = c.f.Read(p)
		if c.ctx.Err() != nil {
			return 0, c.ctx.Err()
		}
		return n, err
	}
}

// ReadAt implements io.ReaderAt interface with context cancellation.
func (c *ctxFile) ReadAt(p []byte, off int64) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
		n, err = c.f.ReadAt(p, off)
		if c.ctx.Err() != nil {
			return 0, c.ctx.Err()
		}
		return n, err
	}
}

// Seek implements io.Seeker interface with context cancellation.
func (c *ctxFile) Seek(offset int64, whence int) (n int64, err error) {
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
		n, err = c.f.Seek(offset, whence)
		if c.ctx.Err() != nil {
			return 0, c.ctx.Err()
		}
		return n, err
	}
}

// HashFileCtx returns the hash of a file with context cancellation support.
func HashFileCtx(ctx context.Context, fname string, algorithm string, showProgress ...bool) (hash []byte, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	defer func() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			hash = nil
			err = ctxErr
		}
	}()
	// Quick context check before starting
	if err = ctx.Err(); err != nil {
		return nil, err
	}

	fstats, err := os.Lstat(fname)
	if err != nil {
		return nil, err
	}

	// Handle symlinks - quick operation, no context needed
	if fstats.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(fname)
		if err != nil {
			return nil, err
		}
		return []byte(SHA256(target)), nil
	}

	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	stopClose := context.AfterFunc(ctx, func() {
		_ = f.Close()
	})
	defer stopClose()

	// Get file info for size (now file is opened, following symlinks if any)
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	// Wrap the file with context support
	cf := NewCtxFile(ctx, f)
	sr := io.NewSectionReader(cf, 0, fi.Size())

	// Parse showProgress parameter
	doShowProgress := false
	if len(showProgress) > 0 {
		doShowProgress = showProgress[0]
	}

	// Create progress bar based on algorithm
	var bar *progressbar.ProgressBar
	if doShowProgress {
		fnameShort := shortenProgressFilename(fname)

		if algorithm == "imohash" {
			// Spinner for imohash (indeterminate progress, max = -1)
			bar = progressbar.NewOptions64(-1,
				progressbar.OptionSetWriter(os.Stderr),
				progressbar.OptionShowBytes(false),
				progressbar.OptionSetDescription(fmt.Sprintf("Sampling %s", fnameShort)),
				progressbar.OptionClearOnFinish(),
				progressbar.OptionFullWidth(),
				progressbar.OptionShowElapsedTimeOnFinish(),
				progressbar.OptionSpinnerType(14),
				progressbar.OptionSetSpinnerChangeInterval(100*time.Millisecond),
			)
		} else {
			// Regular progress bar for other algorithms
			bar = progressbar.NewOptions64(fi.Size(),
				progressbar.OptionSetWriter(os.Stderr),
				progressbar.OptionShowBytes(true),
				progressbar.OptionSetDescription(fmt.Sprintf("Hashing %s", fnameShort)),
				progressbar.OptionClearOnFinish(),
				progressbar.OptionFullWidth(),
			)
		}
	}

	// Dispatch to appropriate hash function
	switch algorithm {
	case "imohash":
		hash, err = IMOHashReader(sr, bar)
	case "md5":
		hash, err = MD5HashReader(sr, bar)
	case "xxhash":
		hash, err = XXHashReader(sr, bar)
	case "highway":
		hash, err = HighwayHashReader(sr, bar)
	default:
		err = fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
	return
}

// MissingChunksCtx returns missing chunk ranges and stops scanning promptly on
// context cancellation. A missing file or size mismatch keeps the legacy
// meaning of an empty range: request the complete file.
func MissingChunksCtx(ctx context.Context, fname string, fsize int64, chunkSize int) (chunkRanges []int64, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if chunkSize <= 0 {
		return nil, fmt.Errorf("chunk size must be positive")
	}
	f, err := os.Open(fname)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	stopClose := context.AfterFunc(ctx, func() {
		_ = f.Close()
	})
	defer stopClose()

	fstat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fstat.Size() != fsize {
		return nil, nil
	}

	var bar *progressbar.ProgressBar
	showProgress := fsize > 10*1024*1024
	if showProgress {
		fnameShort := shortenProgressFilename(fname)
		bar = progressbar.NewOptions64(fsize,
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetDescription(fmt.Sprintf("Checking %s", fnameShort)),
			progressbar.OptionClearOnFinish(),
			progressbar.OptionFullWidth(),
			progressbar.OptionThrottle(100*time.Millisecond),
		)
		defer bar.Finish()
	}

	emptyBuffer := make([]byte, chunkSize)
	chunks := make([]int64, 0)
	var currentLocation int64
	for {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		buffer := make([]byte, chunkSize)
		var bytesRead int
		bytesRead, err = f.Read(buffer)
		if bytesRead > 0 {
			if bytes.Equal(buffer[:bytesRead], emptyBuffer[:bytesRead]) {
				chunks = append(chunks, currentLocation)
			}
			currentLocation += int64(bytesRead)
			if bar != nil {
				_ = bar.Add(bytesRead)
			}
		}
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
	}
	if len(chunks) == 0 {
		return []int64{}, nil
	}

	chunkRanges = []int64{int64(chunkSize), chunks[0]}
	currentCount := int64(1)
	for i := 1; i < len(chunks); i++ {
		if chunks[i]-chunks[i-1] > int64(chunkSize) {
			chunkRanges = append(chunkRanges, currentCount, chunks[i])
			currentCount = 1
			continue
		}
		currentCount++
	}
	chunkRanges = append(chunkRanges, currentCount)
	return chunkRanges, nil
}

// IMOHashReader returns imohash for a SectionReader.
// Uses spinner progress bar for indeterminate progress.
func IMOHashReader(sr *io.SectionReader, bar *progressbar.ProgressBar) ([]byte, error) {
	// Start spinner if provided
	if bar != nil {
		// Add(0) triggers initial render for spinner
		bar.Add(0)
	}

	b, err := imopartial.SumSectionReader(sr)
	if err != nil {
		// If there's an error, finish the bar to clean up display
		if bar != nil {
			bar.Exit()
		}
		return nil, err
	}

	// Finish the progress bar
	if bar != nil {
		bar.Finish()
	}

	return b[:], nil
}

// IMOHashReaderFull returns full imohash (no sampling) for a SectionReader.
func IMOHashReaderFull(sr *io.SectionReader, bar *progressbar.ProgressBar) ([]byte, error) {
	// For full imohash (which reads entire file), use regular progress bar logic
	if bar != nil {
		bar.Add(0) // Start the spinner
	}

	b, err := imofull.SumSectionReader(sr)
	if err != nil {
		if bar != nil {
			bar.Exit()
		}
		return nil, err
	}

	if bar != nil {
		bar.Finish()
	}

	return b[:], nil
}

// MD5HashReader returns MD5 hash for a SectionReader.
func MD5HashReader(sr *io.SectionReader, bar *progressbar.ProgressBar) ([]byte, error) {
	// Reset to beginning
	if _, err := sr.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	h := md5.New()
	if bar != nil {
		// Copy with progress tracking (like original code)
		if _, err := io.Copy(io.MultiWriter(h, bar), sr); err != nil {
			return nil, err
		}
	} else {
		if _, err := io.Copy(h, sr); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

// XXHashReader returns xxhash for a SectionReader.
func XXHashReader(sr *io.SectionReader, bar *progressbar.ProgressBar) ([]byte, error) {
	if _, err := sr.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	h := xxhash.New()
	if bar != nil {
		if _, err := io.Copy(io.MultiWriter(h, bar), sr); err != nil {
			return nil, err
		}
	} else {
		if _, err := io.Copy(h, sr); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

// HighwayHashReader returns highwayhash for a SectionReader.
func HighwayHashReader(sr *io.SectionReader, bar *progressbar.ProgressBar) ([]byte, error) {
	if _, err := sr.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	key, err := hex.DecodeString("1553c5383fb0b86578c3310da665b4f6e0521acf22eb58a99532ffed02a6b115")
	if err != nil {
		return nil, err
	}

	h, err := highwayhash.New(key)
	if err != nil {
		return nil, fmt.Errorf("could not create highwayhash: %w", err)
	}

	if bar != nil {
		if _, err := io.Copy(io.MultiWriter(h, bar), sr); err != nil {
			return nil, err
		}
	} else {
		if _, err := io.Copy(h, sr); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

// Helper function to update existing HashFile to use HashFileCtx
// func HashFile(fname string, algorithm string, showProgress ...bool) ([]byte, error) {
// 	return HashFileCtx(context.Background(), fname, algorithm, showProgress...)
// }
