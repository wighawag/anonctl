package shim

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Stream-level tests for races the forwarder-level tests cannot pin down, because
// they depend on which of two ready events a select picks.

// holdWriteUntilDead is a conn whose Write does not return until the stream it
// belongs to has died. That forces roundTrip to reach its select with the answer
// ALREADY in its channel and the stream ALREADY dead, which is the rare real-world
// interleaving (the peer answers and closes at once) made certain.
type holdWriteUntilDead struct {
	net.Conn
	s atomic.Pointer[dnsStream]
}

func (c *holdWriteUntilDead) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		if s := c.s.Load(); s != nil && !s.live() {
			break
		}
		time.Sleep(time.Millisecond)
	}
	return n, err
}

// TestStream_AnAnswerThatArrivesAsTheStreamDiesIsDelivered: with the answer in hand
// and the stream dead, Go's select picks between the two at random, and an earlier
// version could throw away an answer that had already arrived and report "stream
// broken". Fifty rounds make a coin flip certain to show.
func TestStream_AnAnswerThatArrivesAsTheStreamDiesIsDelivered(t *testing.T) {
	for round := 0; round < 50; round++ {
		client, server := net.Pipe()
		conn := &holdWriteUntilDead{Conn: client}
		s := newDNSStream(conn, time.Minute)
		conn.s.Store(s)

		go func() {
			// Answer the one query, then die at once.
			var l [2]byte
			if _, err := io.ReadFull(server, l[:]); err != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(l[:]))
			if _, err := io.ReadFull(server, q); err != nil {
				return
			}
			resp := aResponse(q, uniqueName, answerIP, 60)
			out := make([]byte, 2+len(resp))
			binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
			copy(out[2:], resp)
			_, _ = server.Write(out)
			server.Close()
		}()

		resp, err := s.roundTrip(buildAQuery(uniqueName), time.Now().Add(3*time.Second))
		if err != nil {
			t.Fatalf("round %d: an answer that had arrived was discarded as %v", round, err)
		}
		if ip := parseFirstA(resp); ip != answerIP {
			t.Fatalf("round %d: resolved to %q, want %q", round, ip, answerIP)
		}
	}
}

// TestStream_AnIdleTeardownThatRacesAQueryIsRetryable: a query can be handed a stream
// in the instant the idle teardown claims it. What that query sees must be
// retryable, so it is re-sent on a fresh stream rather than answered SERVFAIL
// "other" (which is what an earlier version did).
func TestStream_AnIdleTeardownThatRacesAQueryIsRetryable(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	s := newDNSStream(client, time.Minute)
	if !s.failIfIdle() {
		t.Fatal("a stream with nothing in flight must be reapable")
	}
	_, err := s.roundTrip(buildAQuery(uniqueName), time.Now().Add(time.Second))
	if !errors.Is(err, errUpstreamBroken) {
		t.Fatalf("a query that lost the race with the idle teardown got %v; it must be retryable (errUpstreamBroken)", err)
	}
}

// TestStream_TheIdleTeardownNeverTakesAStreamWithAQueryOnIt: the check and the
// teardown are one step, so a registered query cannot be torn down as idle.
func TestStream_TheIdleTeardownNeverTakesAStreamWithAQueryOnIt(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	s := newDNSStream(client, time.Minute)
	if _, err := s.register(make(chan []byte, 1)); err != nil {
		t.Fatal(err)
	}
	if s.failIfIdle() || !s.live() {
		t.Fatal("the idle teardown took a stream with a query registered on it")
	}
	s.fail(errUpstreamClosed)
}
