package ome

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/omecodes/libome/crypt"
	apppb "github.com/omecodes/libome/proto/app"
	authpb "github.com/omecodes/libome/proto/auth"
	"net/http"
)

type Config struct {
	Address             string
	CertificateFilename string
	Key                 string
	Secret              string
}

type Client struct {
	config *Config
	info   *Info
}

func New(c Config) *Client {
	return &Client{config: &c}
}

func (c Client) Info() (*Info, error) {
	if c.info == nil {
		infoEndpoint := fmt.Sprintf("%s/info", c.config.Address)
		var (
			rsp *http.Response
			err error
		)

		if c.config.CertificateFilename != "" {
			hc := http.Client{}
			cert, err := crypt.LoadCertificate(c.config.CertificateFilename)
			if err != nil {
				return nil, err
			}

			pool := x509.NewCertPool()
			pool.AddCert(cert)
			hc.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: pool,
				},
			}
			rsp, err = hc.Get(infoEndpoint)
		} else {
			rsp, err = http.Get(infoEndpoint)
		}

		if err != nil {
			return nil, err
		}

		if rsp == nil {
			return nil, errors.New("an error occurred. Ome server might not be available")
		}

		if rsp.StatusCode == 200 {
			info := new(Info)
			err = json.NewDecoder(rsp.Body).Decode(&info)
			if err != nil {
				return nil, err
			}
			c.info = info
		} else {
			return nil, errors.New("failed to get ome info")
		}
	}

	return c.info, nil
}

func (c Client) Verify(ctx context.Context, t *authpb.JWT) (authpb.JWTState, error) {
	info, err := c.Info()
	if err != nil {
		return 0, err
	}

	key, _, err := crypt.PEMDecodePublicKey([]byte(info.Oauth2.SignatureKey))
	if err != nil {
		return 0, err
	}

	verifier := authpb.NewTokenVerifier(key.(*ecdsa.PublicKey))
	return verifier.Verify(ctx, t)
}

func (c *Client) RegisterUserAttributeDefinition(attrDefs []*apppb.UserAttributeDefinition) error {
	return nil
}
