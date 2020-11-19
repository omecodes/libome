package backend

import (
	"context"
	"encoding/base64"
	"github.com/omecodes/common/errors"
	ome2 "github.com/omecodes/libome"
	"google.golang.org/grpc/metadata"
	"strings"
)

func DetectAuthentication(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, nil
	}

	mdAuthorizations := md.Get("authorization")
	if len(mdAuthorizations) > 0 {
		authorizationHeader := mdAuthorizations[0]
		splits := strings.SplitN(authorizationHeader, " ", 2)

		if strings.ToLower(splits[0]) == "basic" {
			bytes, err := base64.StdEncoding.DecodeString(splits[1])
			if err != nil {
				return nil, errors.Forbidden
			}

			parts := strings.Split(string(bytes), ":")
			if len(parts) != 2 {
				return nil, errors.Forbidden
			}

			user := parts[0]
			var password string
			if len(parts) > 1 {
				password = parts[1]
			}

			ctx = ome2.ContextWithCredentials(ctx, &ome2.Credentials{
				Username: user,
				Password: password,
			})
		} else if strings.ToLower(splits[0]) == "bearer" {
			ctx = ome2.ContextWithOauth2Token(ctx, splits[1])
		}
	}

	mdAuthorizations = md.Get("proxy-authorization")
	if len(mdAuthorizations) > 0 {
		authorizationHeader := mdAuthorizations[0]
		splits := strings.SplitN(authorizationHeader, " ", 2)
		if strings.ToLower(splits[0]) == "basic" {
			bytes, err := base64.StdEncoding.DecodeString(splits[1])
			if err != nil {
				return nil, errors.Forbidden
			}

			parts := strings.Split(string(bytes), ":")
			if len(parts) != 2 {
				return nil, errors.Forbidden
			}
			user := parts[0]
			var secret string
			if len(parts) > 1 {
				secret = parts[1]
			}

			ctx = ome2.ContextWithProxyCredentials(ctx, &ome2.ProxyCredentials{
				Key:    user,
				Secret: secret,
			})
		}
	}

	return ctx, nil
}
