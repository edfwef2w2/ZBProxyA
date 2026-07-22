package udptunnel

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

func TestFrameRoundTrip(t *testing.T) {
	f := Frame{Type: TypeDATA, SessionID: 42, Seq: 3, Ack: 1, Payload: []byte("hello")}
	b, err := EncodeAlloc(&f)
	if err != nil {
		t.Fatal(err)
	}
	var out Frame
	if err := Decode(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Type != f.Type || out.SessionID != f.SessionID || out.Seq != f.Seq || out.Ack != f.Ack {
		t.Fatalf("header mismatch: %+v", out)
	}
	if !bytes.Equal(out.Payload, f.Payload) {
		t.Fatalf("payload %q", out.Payload)
	}
}

func TestFrameReject(t *testing.T) {
	if _, err := EncodeAlloc(&Frame{Payload: make([]byte, MaxPayload+1)}); err != ErrTooLong {
		t.Fatalf("want ErrTooLong, got %v", err)
	}
	var f Frame
	if err := Decode([]byte{1, 2, 3}, &f); err != ErrTooShort {
		t.Fatalf("want ErrTooShort, got %v", err)
	}
}

func TestDialListenEcho(t *testing.T) {
	ln, err := ListenUDP("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		_, err = c.Write(buf[:n])
		errCh <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli, err := Dial(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	msg := []byte("ping-tunnel")
	if _, err := cli.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("got %q", buf[:n])
	}
	if err := <-errCh; err != nil && err != io.EOF {
		t.Fatal(err)
	}
}

func TestDialListenLarge(t *testing.T) {
	ln, err := ListenUDP("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	payload := bytes.Repeat([]byte("0123456789abcdef"), 256) // 4 KiB
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		got := make([]byte, 0, len(payload))
		buf := make([]byte, 1024)
		for len(got) < len(payload) {
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := c.Read(buf)
			if err != nil {
				done <- err
				return
			}
			got = append(got, buf[:n]...)
		}
		if !bytes.Equal(got, payload) {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, err = c.Write([]byte("ok"))
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cli, err := Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := cli.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	_ = cli.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ok" {
		t.Fatalf("got %q", buf[:n])
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProbeRTT(t *testing.T) {
	ln, err := ListenUDP("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rtt, err := ProbeRTT(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if rtt <= 0 || rtt > time.Second {
		t.Fatalf("unexpected rtt %v", rtt)
	}
}
