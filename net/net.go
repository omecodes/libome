package net

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/omecodes/libome/crypt"
	"net"
)

type ListenOptions struct {
	trust        bool
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
		opts.tc = tc
		opts.certFilename = ""
		opts.keyFilename = ""
	}
}

// WithTLSParams adds tls config params
// specifies certificate and key filenames for tls config
// And adds the list of client authority certificate filenames for tls config
func WithTLSParams(selfSigned bool, certFilename, keyFilename string, clientCARootFilenames ...string) ListenOption {
	return func(opts *ListenOptions) {
		opts.secure = certFilename != "" && keyFilename != ""
		opts.clientCAs = append(opts.clientCAs, clientCARootFilenames...)
		opts.trust = selfSigned
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

		if lopts.trust {
			pool := x509.NewCertPool()
			pool.AddCert(cert)
			tc.ClientCAs = pool
		}

		return tls.Listen("tcp", address, tc)

	} else if lopts.tc != nil {
		return tls.Listen("tcp", address, lopts.tc)
	} else {
		return net.Listen("tcp", address)
	}
}
