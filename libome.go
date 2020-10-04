package ome

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/omecodes/libome/crypt"
)

// GetInfo retrieves Ome services info
func GetInfo(host string, certFilename string) (*Info, error) {
	infoEndpoint := fmt.Sprintf("https://%s/info", host)
	var (
		rsp *http.Response
		err error
	)

	if certFilename != "" {
		hc := http.Client{}
		cert, err := crypt.LoadCertificate(certFilename)
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
		return info, nil
	} else {
		return nil, errors.New("failed to get ome info")
	}
}
