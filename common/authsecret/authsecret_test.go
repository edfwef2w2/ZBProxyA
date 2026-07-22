package authsecret

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	b, err := Normalize("")
	if err != nil || b != nil {
		t.Fatalf("empty: got %v %v", b, err)
	}
	b, err = Normalize("hello")
	if err != nil || string(b) != "hello" {
		t.Fatalf("hello: got %q %v", b, err)
	}
	long := string(bytes.Repeat([]byte("a"), MaxLen+1))
	if _, err = Normalize(long); err != ErrTooLong {
		t.Fatalf("expected ErrTooLong, got %v", err)
	}
}

func TestWriteVerifyRoundTrip(t *testing.T) {
	secret, err := Normalize("super-secret-key-32bytes!!!!!!")
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- Write(c1, secret)
	}()
	if err := Verify(c2, secret, time.Second); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestVerifyMismatch(t *testing.T) {
	want, _ := Normalize("correct-secret-here!!!!!!!!")
	got, _ := Normalize("wrong-secret-here!!!!!!!!!!")
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go Write(c1, got)
	if err := Verify(c2, want, time.Second); err != ErrMismatch {
		t.Fatalf("expected ErrMismatch, got %v", err)
	}
}

func TestVerifyShortRead(t *testing.T) {
	want, _ := Normalize("long-enough-secret-value!!!!")
	c1, c2 := net.Pipe()
	defer c2.Close()

	go func() {
		c1.Write([]byte("short"))
		c1.Close()
	}()
	if err := Verify(c2, want, time.Second); err != ErrShortRead {
		t.Fatalf("expected ErrShortRead, got %v", err)
	}
}

func TestVerifyTimeout(t *testing.T) {
	want, _ := Normalize("timeout-secret-value!!!!!!!!")
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// peer never writes
	err := Verify(c2, want, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if err == ErrMismatch || err == ErrShortRead || err == ErrEmpty {
		t.Fatalf("unexpected error type: %v", err)
	}
}

func TestWriteEmptyNoOp(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if err := Write(c1, nil); err != nil {
		t.Fatal(err)
	}
	// nothing should be readable without blocking forever — close writer side
	c1.Close()
	buf := make([]byte, 1)
	n, err := c2.Read(buf)
	if n != 0 || err != io.EOF {
		t.Fatalf("expected EOF with 0 bytes, got n=%d err=%v", n, err)
	}
}
