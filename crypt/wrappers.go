package crypt

import "io"

type ReadCloserWrapper interface {
	Wrap(reader io.ReadCloser) io.ReadCloser
}

type ReaderWrapper interface {
	Wrap(reader io.Reader) io.Reader
}

type WriterWrapper interface {
	Wrap(writer io.Writer) io.Writer
}

type WriteCloserWrapper interface {
	Wrap(writer io.WriteCloser) io.WriteCloser
}
