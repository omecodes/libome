package ome

import "context"

type ctxProxyCredentials struct{}
type ctxCredentials struct{}
type ctxOauth2Token struct{}
type ctxJwt struct{}

func ContextWithJWT(ctx context.Context, j string) context.Context {
	return context.WithValue(ctx, ctxJwt{}, j)
}

func ContextWithCredentials(ctx context.Context, c *Credentials) context.Context {
	return context.WithValue(ctx, ctxCredentials{}, c)
}

func ContextWithProxyCredentials(ctx context.Context, credentials2 *ProxyCredentials) context.Context {
	return context.WithValue(ctx, ctxProxyCredentials{}, credentials2)
}

func ContextWithOauth2Token(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxOauth2Token{}, token)
}

func CredentialsFromContext(ctx context.Context) *Credentials {
	o := ctx.Value(ctxCredentials{})
	if o == nil {
		return nil
	}
	return o.(*Credentials)
}

func ProxyCredentialsFromContext(ctx context.Context) *ProxyCredentials {
	o := ctx.Value(ctxProxyCredentials{})
	if o == nil {
		return nil
	}
	return o.(*ProxyCredentials)
}

func JWTFromContext(ctx context.Context) string {
	o := ctx.Value(ctxJwt{})
	if o == nil {
		return ""
	}

	return o.(string)
}

func GetOauth2Token(ctx context.Context) string {
	o := ctx.Value(ctxOauth2Token{})
	if o == nil {
		return ""
	}

	return o.(string)
}

type CredentialsVerifyFunc func(cred *Credentials) (bool, error)

type ProxyCredentialsVerifyFunc func(cred *ProxyCredentials) (bool, error)

type Credentials struct {
	Username string
	Password string
}

type ProxyCredentials struct {
	Key    string
	Secret string
}

type token struct{}

func TokenFromContext(ctx context.Context) *JWT {
	o := ctx.Value(token{})
	if c, ok := o.(*JWT); ok {
		return c
	}
	return nil
}

func ContextWithToken(ctx context.Context, t *JWT) context.Context {
	return context.WithValue(ctx, token{}, t)
}
