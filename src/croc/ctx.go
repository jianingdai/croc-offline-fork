// ctx.go
package croc

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/schollz/croc/v10/src/message"
	"github.com/schollz/croc/v10/src/tcp"
	"github.com/schollz/croc/v10/src/utils"
	log "github.com/schollz/logger"
)

// stop manages graceful shutdown
type stop struct {
	parent     context.Context
	ctx        context.Context
	cancel     context.CancelFunc
	stopChan   chan struct{} //peerdiscovery
	cancelOnce sync.Once
	doneOnce   sync.Once
	run        func(debugLevel string, host string, port string, password string, banner ...string) (err error)
	hash       func(fname string, algorithm string, showProgress ...bool) (hash256 []byte, err error)
	gui        bool
}

// newStop creates a new stop manager instance
func newStop(ctx context.Context) *stop {
	s := &stop{
		stopChan: make(chan struct{}),
		run:      tcp.Run,
		hash:     utils.HashFile,
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.parent = ctx
	s.ctx, s.cancel = context.WithCancel(ctx)
	context.AfterFunc(s.ctx, s.signalDone)

	return s
}

func (s *stop) signalDone() {
	s.doneOnce.Do(func() {
		close(s.stopChan)
		log.Trace("croc done")
	})
}

func (s *stop) done() {
	<-s.ctx.Done()
	s.signalDone()
}

// NewCtx creates a client with context support
func NewCtx(ctx context.Context, ops Options) (*Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// Create a regular c
	c, err := New(ops)
	if err != nil {
		return nil, err
	}
	c.stop = newStop(ctx)
	c.stop.gui = true
	c.stop.run = func(debugLevel string, host string, port string, password string, banner ...string) (err error) {
		return tcp.RunCtx(c.stop.ctx, debugLevel, host, port, password, banner...)
	}
	c.stop.hash = func(fname string, algorithm string, showProgress ...bool) (hash256 []byte, err error) {
		return utils.HashFileCtx(c.stop.ctx, fname, algorithm, showProgress...)
	}

	return c, nil
}

// ctxErr checks whether it is necessary to interrupt my loops and goroutines
func (s *stop) ctxErr() error {
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	default:
		return nil
	}
}

func (s *stop) parentErr() error {
	if s.parent == nil {
		return nil
	}
	return s.parent.Err()
}

func (c *Client) bindFileToContext(file *os.File) error {
	if file == nil {
		return nil
	}
	context.AfterFunc(c.stop.ctx, func() {
		_ = file.Close()
	})
	if err := c.ctxErr(); err != nil {
		_ = file.Close()
		return err
	}
	return nil
}

// Cancel initiates interruption of my loops and goroutines
func (s *stop) Cancel() {
	log.Trace("croc Cancel")
	s.cancelOnce.Do(s.cancel)
}

// SendError tells the peer to interrupt their loops and goroutines
func (c *Client) SendError() {
	if c.ctxErr() != nil {
		return
	}
	if c.Key != nil && len(c.conn) > 0 && c.conn[0] != nil {
		if err := message.Send(c.conn[0], c.Key, message.Message{
			Type:    message.TypeError,
			Message: "refusing files",
		}); err == nil {
			_ = utils.WaitContext(c.stop.ctx, time.Millisecond)
		}
	}
}
