package diago

import (
	"io"
	"sync/atomic"
)

type audioControl struct {
	Reader io.Reader // MUST be set if usede as reader
	Writer io.Writer // Must be set if used as writer

	muted atomic.Bool
	stop  atomic.Bool
}

func (c *audioControl) Read(b []byte) (n int, err error) {
	if c.stop.Load() {
		return 0, io.EOF
	}

	n, err = c.Reader.Read(b)
	if err != nil {
		return n, err
	}

	if c.muted.Load() {
		for i := range b[:n] {
			b[i] = 0
		}
	}

	return n, err
}

func (c *audioControl) Write(b []byte) (n int, err error) {
	if c.stop.Load() {
		return 0, io.EOF
	}

	if c.muted.Load() {
		for i := range b {
			b[i] = 0
		}
	}

	return c.Writer.Write(b)
}

func (c *audioControl) Mute(mute bool) {
	c.muted.Store(mute)
}

// Stop will stop reader/writer and return io.Eof
func (c *audioControl) Stop() {
	c.stop.Store(true)
}

type AudioMuter struct {
	Reader io.Reader // MUST be set if usede as reader
	Writer io.Writer // Must be set if used as writer

	muted atomic.Bool
}

func (c *AudioMuter) Read(b []byte) (n int, err error) {
	n, err = c.Reader.Read(b)
	if err != nil {
		return n, err
	}

	if c.muted.Load() {
		for i := range b[:n] {
			b[i] = 0
		}
	}

	return n, err
}

func (c *AudioMuter) Write(b []byte) (n int, err error) {
	if c.muted.Load() {
		for i := range b {
			b[i] = 0
		}
	}

	return c.Writer.Write(b)
}

func (c *AudioMuter) Mute(mute bool) {
	c.muted.Store(mute)
}

type AudioStopper struct {
	Reader io.Reader // MUST be set if usede as reader
	Writer io.Writer // Must be set if used as writer

	stop atomic.Bool
}

func (c *AudioStopper) Read(b []byte) (n int, err error) {
	if c.stop.Load() {
		return 0, io.EOF
	}

	n, err = c.Reader.Read(b)
	if err != nil {
		return n, err
	}

	return n, err
}

func (c *AudioStopper) Write(b []byte) (n int, err error) {
	if c.stop.Load() {
		return 0, io.EOF
	}

	return c.Writer.Write(b)
}

// Stop will stop reader/writer and return io.Eof
func (c *AudioStopper) Stop() {
	c.stop.Store(true)
}
