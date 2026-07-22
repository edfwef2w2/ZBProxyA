package udptunnel

import (
	"net"
	"time"
)

// Conn implements net.Conn over a tunnel session.
type Conn struct {
	sess       *session
	localAddr  net.Addr
	remoteAddr net.Addr
	readDl     time.Time
	writeDl    time.Time
}

func newConn(sess *session, local, remote net.Addr) *Conn {
	return &Conn{sess: sess, localAddr: local, remoteAddr: remote}
}

func (c *Conn) Read(b []byte) (int, error) {
	if !c.readDl.IsZero() {
		// wake path: session read blocks; use short poll via deadline on wait
		for {
			if time.Now().After(c.readDl) {
				return 0, errTimeout{}
			}
			c.sess.mu.Lock()
			if len(c.sess.readBuf) > 0 || c.sess.readEOF || c.sess.closed {
				c.sess.mu.Unlock()
				return c.sess.read(b)
			}
			ch := c.sess.readWait
			c.sess.mu.Unlock()
			timer := time.NewTimer(time.Until(c.readDl))
			select {
			case <-ch:
				timer.Stop()
			case <-timer.C:
				return 0, errTimeout{}
			}
		}
	}
	return c.sess.read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	if !c.writeDl.IsZero() && time.Now().After(c.writeDl) {
		return 0, errTimeout{}
	}
	return c.sess.write(b)
}

func (c *Conn) Close() error                 { return c.sess.close() }
func (c *Conn) LocalAddr() net.Addr          { return c.localAddr }
func (c *Conn) RemoteAddr() net.Addr         { return c.remoteAddr }
func (c *Conn) SetDeadline(t time.Time) error {
	c.readDl, c.writeDl = t, t
	return nil
}
func (c *Conn) SetReadDeadline(t time.Time) error  { c.readDl = t; return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { c.writeDl = t; return nil }

type errTimeout struct{}

func (errTimeout) Error() string   { return "udptunnel: i/o timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }
