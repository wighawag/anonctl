package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// blockingReader never yields data and never returns: it models os.Stdin waiting
// for the operator to type + press Enter. readLineContext must NOT wait for it when
// the context is cancelled.
type blockingReader struct{}

func (blockingReader) Read(p []byte) (int, error) { select {} }

// A Ctrl+C (cancelled context) at the prompt must surface IMMEDIATELY, without
// waiting for the blocking stdin read to return (which, without an Enter, never
// does). readLineContext races the read against ctx.Done and returns a cancelled
// error promptly.
func TestReadLineContextReturnsOnCancelWithoutEnter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: the Ctrl+C arrived

	done := make(chan struct{})
	var gotErr error
	go func() {
		_, gotErr = readLineContext(ctx, blockingReader{})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLineContext blocked on a cancelled context: it must return without waiting for Enter (the Ctrl+C responsiveness bug)")
	}
	if !errors.Is(gotErr, context.Canceled) {
		t.Errorf("readLineContext on a cancelled context = %v, want a wrapped context.Canceled", gotErr)
	}
	if gotErr != nil && !strings.Contains(gotErr.Error(), "cancelled") {
		t.Errorf("the error should read as a cancel to the operator; got %q", gotErr.Error())
	}
}

// When a line IS available before any cancel, readLineContext returns it normally
// (the happy path is unchanged by the context race).
func TestReadLineContextReturnsLine(t *testing.T) {
	line, err := readLineContext(context.Background(), strings.NewReader("2\n"))
	if err != nil {
		t.Fatalf("readLineContext: %v", err)
	}
	if strings.TrimSpace(line) != "2" {
		t.Errorf("readLineContext read %q, want \"2\"", line)
	}
}

var _ io.Reader = blockingReader{}
