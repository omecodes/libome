package net

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/omecodes/libome/crypt"
	"net"
)

type ListenOptions struct {
	certFilename string
	keyFilename  string
	clientCAs    []string
	tc           *tls.Config
	secure       bool
	keyPassword  []byte
}

// ListenOption enriches listen options object
type ListenOption func(opts *ListenOptions)

// WithTLSConfig set tls config for connection listen
func WithTLSConfig(tc *tls.Config) ListenOption {
	return func(opts *ListenOptions) {
		opts.secure = tc != nil
		opts.certFilename = ""
		opts.keyFilename = ""
		opts.clientCAs = nil
		opts.tc = tc
	}
}

// WithTLSParams adds tls config params
// specifies certificate and key filenames for tls config
// And adds the list of client authority certificate filenames for tls config
func WithTLSParams(certFilename, keyFilename string, clientCARootFilenames ...string) ListenOption {
	return func(opts *ListenOptions) {
		opts.secure = certFilename != "" && keyFilename != ""
		opts.clientCAs = append(opts.clientCAs, clientCARootFilenames...)
		opts.tc = nil
		opts.certFilename = certFilename
		opts.keyFilename = keyFilename
	}
}

// KeyPassword passed if the key filename is protected
func KeyPassword(password []byte) ListenOption {
	return func(opts *ListenOptions) {
		opts.keyPassword = password
	}
}

// Listen listen to tcp connections
func Listen(address string, opts ...ListenOption) (net.Listener, error) {
	var lopts ListenOptions
	for _, opt := range opts {
		opt(&lopts)
	}

	if address == "" {
		address = ":"
	}

	if lopts.certFilename != "" && lopts.keyFilename != "" {
		cert, err := crypt.LoadCertificate(lopts.certFilename)
		if err != nil {
			return nil, err
		}

		key, err := crypt.LoadPrivateKey(lopts.keyPassword, lopts.keyFilename)
		if err != nil {
			return nil, err
		}

		tc := &tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{cert.Raw},
					PrivateKey:  key,
				},
			},
		}

		if len(lopts.clientCAs) > 0 {
			pool := x509.NewCertPool()
			for _, filename := range lopts.clientCAs {
				cert, err := crypt.LoadCertificate(filename)
				if err != nil {
					return nil, err
				}
				pool.AddCert(cert)
			}
			tc.ClientCAs = pool
		}

		return tls.Listen("tcp", address, tc)

	} else if lopts.tc != nil {
		return tls.Listen("tcp", address, lopts.tc)
	} else {
		return net.Listen("tcp", address)
	}
}
