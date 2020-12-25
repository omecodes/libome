package ome

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/omecodes/libome/logs"
)

type GrpcContextInterceptor interface {
	UnaryUpdate(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error)
	StreamUpdate(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error
}

type interceptorChain struct {
	interceptors []GrpcContextUpdater
}

func (interceptor *interceptorChain) UnaryUpdate(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var err error
	start := time.Now()
	method := path.Base(info.FullMethod)

	for _, i := range interceptor.interceptors {
		ctx, err = i.UpdateContext(ctx)
		if err != nil {
			return nil, err
		}
	}
	rsp, err := handler(ctx, req)
	if err != nil {
		logs.Error(fmt.Sprintf("GRPC %s", method), logs.Field("request", req), logs.Err(err), logs.Field("duration", time.Since(start)))
	} else {
		logs.Info(fmt.Sprintf("GRPC %s", method), logs.Field("req", req), logs.Field("rsp", rsp), logs.Field("duration", time.Since(start)))
	}
	return rsp, err
}

func (interceptor *interceptorChain) StreamUpdate(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	var err error
	start := time.Now()
	method := path.Base(info.FullMethod)
	ctx := ss.Context()
	for _, i := range interceptor.interceptors {
		ctx, err = i.UpdateContext(ctx)
	}
	ss = GRPCStream(ctx, ss)
	err = handler(srv, ss)
	if err != nil {
		logs.Error(fmt.Sprintf("GRPC %s", method), logs.Err(err), logs.Field("duration", time.Since(start)))
	} else {
		logs.Info(fmt.Sprintf("GRPC %s", method), logs.Field("duration", time.Since(start)))
	}
	return err
}

// NewGrpcContextInterceptor is a chain of interceptors
func NewGrpcContextInterceptor(i ...GrpcContextUpdater) GrpcContextInterceptor {
	return &interceptorChain{interceptors: i}
}

// GRPCContextUpdater is a context wrapper which is executed when gRPC function is called
// it can be use to enrich context or verify authentication.
type GrpcContextUpdater interface {
	// Intercept gets token works with and return a new token
	UpdateContext(ctx context.Context) (context.Context, error)
}

// InterceptorFunc is an interceptor function
type GrpcContextUpdaterFunc func(ctx context.Context) (context.Context, error)

// Intercept gets token works with and return a new token
func (interceptorFunc GrpcContextUpdaterFunc) UpdateContext(ctx context.Context) (context.Context, error) {
	return interceptorFunc(ctx)
}

// JwtVerifyFunc is a function that verify jwt passed through authorization header
type JwtVerifyFunc func(ctx context.Context, jwt string) (context.Context, error)

type jwtVerifier struct {
	verifyFunc JwtVerifyFunc
}

func (j *jwtVerifier) UpdateContext(ctx context.Context) (context.Context, error) {
	var err error

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, nil
	}

	meta := md.Get("authorization")
	if len(meta) != 0 {
		authorization := meta[0]
		head := authorization[:7]
		if strings.HasPrefix(strings.ToLower(head), "bearer ") {
			ctx, err = j.verifyFunc(ctx, authorization[7:])
			if err != nil {
				//log.Error("failed to verify token", log.Err(err))
				//err = errors.Unauthorized
				err = errors.New("unauthorized")
			}
		}
	}

	return ctx, err
}

// NewJwtVerifierInterceptor returns a wrapper that detects bearer authorization
func NewJwtVerifierInterceptor(verifyFunc JwtVerifyFunc) *jwtVerifier {
	return &jwtVerifier{
		verifyFunc: verifyFunc,
	}
}

type proxyBasic struct{}

func (b *proxyBasic) UpdateContext(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		//return nil, errors.Forbidden
		return nil, errors.New("forbidden")
	}

	meta := md.Get("proxy-authorization")
	if len(meta) == 0 {
		return ctx, nil
	}

	authorization := meta[0]
	if strings.HasPrefix(authorization, "Basic ") {
		authorization = strings.TrimPrefix(authorization, "Basic ")

		decodedBytes, err := base64.StdEncoding.DecodeString(authorization)
		if err != nil {
			//return nil, errors.Forbidden
			return nil, errors.New("forbidden")
		}

		var key string
		var secret string

		splits := strings.Split(string(decodedBytes), ":")
		key = splits[0]
		if len(splits) > 1 {
			secret = splits[1]
		}

		ctx = ContextWithProxyCredentials(ctx, &ProxyCredentials{
			Key:    key,
			Secret: secret,
		})
	}
	return ctx, nil
}

// NewProxyBasicInterceptor returns a context wrapper that detects proxy authorization
func NewProxyBasicInterceptor() *proxyBasic {
	return &proxyBasic{}
}
