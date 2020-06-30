// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package telemetry

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"sync"

	logger "github.com/open-ness/common/log"
)

const (
	// SyslogSNI is the server name for TLS when connecting to the Controller
	// for Syslog ingress
	SyslogSNI = "syslog.controller.openness"

	// StatsdSNI is the server name for TLS when connecting to the Controller
	// for StatsD ingress
	StatsdSNI = "statsd.controller.openness"
)

// MaxUDPPacketSize is the maximum size of the packet (64kb) minus the UDP
// header (8 bytes) and the IP header (20 bytes minimum for IPv4).
const MaxUDPPacketSize = 64*1024 - 8 - 20

var log = logger.DefaultLogger.WithField("pkg", "telemetry")

// AcceptTCP wraps the Accept method on a TCP listener.
func AcceptTCP(lis net.Listener) func() (io.ReadCloser, error) {
	// TODO: consider removing any deadlines on the listener
	return func() (io.ReadCloser, error) { return lis.Accept() }
}

// AcceptUDP accepts new UDP connections and returns a reader that reads up to
// one full packet at a time with a newline always appended. The appended
// newline ensures that packets are delimited as long as one full packet is
// read at a time. Therefore it is important that each read is done into a
// buffer with enough space for a UDP packet and a newline character.
func AcceptUDP(ctx context.Context, addr string) func() (io.ReadCloser, error) {
	// Use a channel as a semaphore to accept one connection at a time. One
	// conn is accepted for each message received on the channel. The channel
	// starts with one message on the buffer and receives another each time the
	// conn is closed.
	next := make(chan struct{}, 1)
	next <- struct{}{}
	return func() (io.ReadCloser, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-next:
			conn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", addr)
			for err != nil {
				// retry on temporary errors
				if netErr, ok := err.(*net.OpError); !ok || !netErr.Temporary() {
					// retry on bind errors
					if syscallErr, ok := netErr.Err.(*os.SyscallError); !ok || syscallErr.Syscall == "bind" {
						return nil, err
					}
				}
				conn, err = (&net.ListenConfig{}).ListenPacket(ctx, "udp", addr)
			}
			return struct {
				io.Reader
				io.Closer
			}{
				Reader: newlineReader{conn.(*net.UDPConn)},
				Closer: &notifyCloser{Closer: conn, ch: next},
			}, nil
		}
	}
}

// newlineReader reads n-1 bytes from a Reader and then appends a newline
// character on each call to Read.
type newlineReader struct {
	io.Reader
}

func (rc newlineReader) Read(p []byte) (int, error) {
	n, err := rc.Reader.Read(p[:len(p)-2])
	if err != nil {
		return n, err
	}
	if p[n-1] == '\n' {
		return n, nil
	}
	p[n] = '\n'
	return n + 1, nil
}

// notifyCloser sends on a channel whenever Close is called. The channel should
// be buffered enough so that this send is never blocked.
type notifyCloser struct {
	io.Closer

	once sync.Once
	ch   chan<- struct{}
}

func (nc *notifyCloser) Close() error {
	err := nc.Closer.Close()
	nc.once.Do(func() { nc.ch <- struct{}{} })
	return err
}

// WriteToByLine accepts inbound connections and concurrently writes the lines
// directly to disk. By using the AcceptTCP and AcceptUDP helper functions,
// newlines are handled properly.
//
// Setting a buffer size is optional for TCP or any stream-based protocol, but
// recommended for packet protocols such as UDP unless the caller can be sure
// that all packet contents will end with a newline.
//
// When expecting packets without a guaranteed newline ending, the read buffer
// size must be large enough for the complete contents of a UDP packet and a
// newline. For UDP over IP, it is safe to use a bufSize of MaxUDPPacketSize+1.
func WriteToByLine(w io.Writer, bufSize int, accept func() (io.ReadCloser, error)) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Synchronize line writes to log file
	lines := make(chan []byte, 100) // reasonable buffer for reduce conn read blocking
	go writeLines(ctx, w, lines)

	for {
		rc, err := accept()
		if err != nil {
			return err
		}
		var buf []byte
		if bufSize > 0 {
			buf = make([]byte, bufSize)
		}
		go scanLines(ctx, rc, lines, buf)
	}
}

func writeLines(ctx context.Context, w io.Writer, lines <-chan []byte) {
	for {
		select {
		case <-ctx.Done():
			return
		case line := <-lines:
			_, err := w.Write(append(line, '\n'))
			if err != nil {
				log.Errf("error writing to telemetry file: %v", err)
			}
		}
	}
}

func scanLines(ctx context.Context, rc io.ReadCloser, lines chan<- []byte, buf []byte) {
	// Scan conn by line
	done := make(chan struct{})
	go func() {
		defer close(done)

		// Create a scanner with enough buffer space for the maximum size of a
		// UDP packet (64kb) plus a newline (1b)
		sc := bufio.NewScanner(rc)
		if buf != nil {
			sc.Buffer(buf, cap(buf))
		}
		for sc.Scan() {
			select {
			case <-ctx.Done():
				return
			case lines <- sc.Bytes():
			}
		}
		if err := sc.Err(); err != nil {
			log.Errf("error reading from telemetry conn: %v", err)
		}
	}()

	// Close conn when listener shuts down or scanner finishes
	select {
	case <-ctx.Done():
	case <-done:
	}
	if err := rc.Close(); err != nil {
		log.Errf("error closing telemetry conn: %v", err)
	}
}
