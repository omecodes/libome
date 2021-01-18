package crypt

import (
	"io"
)

type AESGCMDecryptWrapper struct {
	key  []byte
	opts []ReadOption
}

func (d *AESGCMDecryptWrapper) WrapReader(reader io.Reader) io.Reader {
	r := newAesGCMDecryptReader(d.key, reader, d.opts...)
	return r
}

func (d *AESGCMDecryptWrapper) WrapReadCloser(readCloser io.ReadCloser) io.ReadCloser {
	rc := newAesGCMDecryptReader(d.key, readCloser, d.opts...)
	rc.closer = readCloser
	return rc
}

func NewDecryptWrapper(key []byte, opts ...ReadOption) *AESGCMDecryptWrapper {
	return &AESGCMDecryptWrapper{
		key:  key,
		opts: opts,
	}
}
