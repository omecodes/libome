// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package filespb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion7

// FilesClient is the client API for Files service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type FilesClient interface {
	Sync(ctx context.Context, in *SyncMessage, opts ...grpc.CallOption) (Files_SyncClient, error)
	List(ctx context.Context, in *ListRequest, opts ...grpc.CallOption) (*ListResponse, error)
	GetListStream(ctx context.Context, in *GetListStreamRequest, opts ...grpc.CallOption) (Files_GetListStreamClient, error)
	Create(ctx context.Context, in *CreateRequest, opts ...grpc.CallOption) (*CreateResponse, error)
	GetStats(ctx context.Context, in *StatsRequest, opts ...grpc.CallOption) (*StatsResponse, error)
	StatsSession(ctx context.Context, opts ...grpc.CallOption) (Files_StatsSessionClient, error)
	GetMeta(ctx context.Context, in *GetMetaRequest, opts ...grpc.CallOption) (*GetMetaResponse, error)
	SetMeta(ctx context.Context, in *SetMetaRequest, opts ...grpc.CallOption) (*SetMetaResponse, error)
	DownloadURL(ctx context.Context, in *DownloadURLRequest, opts ...grpc.CallOption) (*DownloadURLResponse, error)
	UploadURL(ctx context.Context, in *UploadURLRequest, opts ...grpc.CallOption) (*UploadURLResponse, error)
	Copy(ctx context.Context, in *CopyRequest, opts ...grpc.CallOption) (*CopyResponse, error)
	Move(ctx context.Context, in *MoveRequest, opts ...grpc.CallOption) (*MoveResponse, error)
	Delete(ctx context.Context, in *DeleteRequest, opts ...grpc.CallOption) (*DeleteResponse, error)
}

type filesClient struct {
	cc grpc.ClientConnInterface
}

func NewFilesClient(cc grpc.ClientConnInterface) FilesClient {
	return &filesClient{cc}
}

func (c *filesClient) Sync(ctx context.Context, in *SyncMessage, opts ...grpc.CallOption) (Files_SyncClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Files_serviceDesc.Streams[0], "/Files/Sync", opts...)
	if err != nil {
		return nil, err
	}
	x := &filesSyncClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Files_SyncClient interface {
	Recv() (*Event, error)
	grpc.ClientStream
}

type filesSyncClient struct {
	grpc.ClientStream
}

func (x *filesSyncClient) Recv() (*Event, error) {
	m := new(Event)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *filesClient) List(ctx context.Context, in *ListRequest, opts ...grpc.CallOption) (*ListResponse, error) {
	out := new(ListResponse)
	err := c.cc.Invoke(ctx, "/Files/List", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *filesClient) GetListStream(ctx context.Context, in *GetListStreamRequest, opts ...grpc.CallOption) (Files_GetListStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Files_serviceDesc.Streams[1], "/Files/GetListStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &filesGetListStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Files_GetListStreamClient interface {
	Recv() (*Stats, error)
	grpc.ClientStream
}

type filesGetListStreamClient struct {
	grpc.ClientStream
}

func (x *filesGetListStreamClient) Recv() (*Stats, error) {
	m := new(Stats)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *filesClient) Create(ctx context.Context, in *CreateRequest, opts ...grpc.CallOption) (*CreateResponse, error) {
	out := new(CreateResponse)
	err := c.cc.Invoke(ctx, "/Files/Create", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *filesClient) GetStats(ctx context.Context, in *StatsRequest, opts ...grpc.CallOption) (*StatsResponse, error) {
	out := new(StatsResponse)
	err := c.cc.Invoke(ctx, "/Files/GetStats", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *filesClient) StatsSession(ctx context.Context, opts ...grpc.CallOption) (Files_StatsSessionClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Files_serviceDesc.Streams[2], "/Files/StatsSession", opts...)
	if err != nil {
		return nil, err
	}
	x := &filesStatsSessionClient{stream}
	return x, nil
}

type Files_StatsSessionClient interface {
	Send(*StatsRequest) error
	Recv() (*Stats, error)
	grpc.ClientStream
}

type filesStatsSessionClient struct {
	grpc.ClientStream
}

func (x *filesStatsSessionClient) Send(m *StatsRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *filesStatsSessionClient) Recv() (*Stats, error) {
	m := new(Stats)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *filesClient) GetMeta(ctx context.Context, in *GetMetaRequest, opts ...grpc.CallOption) (*GetMetaResponse, error) {
	out := new(GetMetaResponse)
	err := c.cc.Invoke(ctx, "/Files/GetMeta", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *filesClient) SetMeta(ctx context.Context, in *SetMetaRequest, opts ...grpc.CallOption) (*SetMetaResponse, error) {
	out := new(SetMetaResponse)
	err := c.cc.Invoke(ctx, "/Files/SetMeta", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *filesClient) DownloadURL(ctx context.Context, in *DownloadURLRequest, opts ...grpc.CallOption) (*DownloadURLResponse, error) {
	out := new(DownloadURLResponse)
	err := c.cc.Invoke(ctx, "/Files/DownloadURL", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *filesClient) UploadURL(ctx context.Context, in *UploadURLRequest, opts ...grpc.CallOption) (*UploadURLResponse, error) {
	out := new(UploadURLResponse)
	err := c.cc.Invoke(ctx, "/Files/UploadURL", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *filesClient) Copy(ctx context.Context, in *CopyRequest, opts ...grpc.CallOption) (*CopyResponse, error) {
	out := new(CopyResponse)
	err := c.cc.Invoke(ctx, "/Files/Copy", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *filesClient) Move(ctx context.Context, in *MoveRequest, opts ...grpc.CallOption) (*MoveResponse, error) {
	out := new(MoveResponse)
	err := c.cc.Invoke(ctx, "/Files/Move", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *filesClient) Delete(ctx context.Context, in *DeleteRequest, opts ...grpc.CallOption) (*DeleteResponse, error) {
	out := new(DeleteResponse)
	err := c.cc.Invoke(ctx, "/Files/Delete", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FilesServer is the server API for Files service.
// All implementations must embed UnimplementedFilesServer
// for forward compatibility
type FilesServer interface {
	Sync(*SyncMessage, Files_SyncServer) error
	List(context.Context, *ListRequest) (*ListResponse, error)
	GetListStream(*GetListStreamRequest, Files_GetListStreamServer) error
	Create(context.Context, *CreateRequest) (*CreateResponse, error)
	GetStats(context.Context, *StatsRequest) (*StatsResponse, error)
	StatsSession(Files_StatsSessionServer) error
	GetMeta(context.Context, *GetMetaRequest) (*GetMetaResponse, error)
	SetMeta(context.Context, *SetMetaRequest) (*SetMetaResponse, error)
	DownloadURL(context.Context, *DownloadURLRequest) (*DownloadURLResponse, error)
	UploadURL(context.Context, *UploadURLRequest) (*UploadURLResponse, error)
	Copy(context.Context, *CopyRequest) (*CopyResponse, error)
	Move(context.Context, *MoveRequest) (*MoveResponse, error)
	Delete(context.Context, *DeleteRequest) (*DeleteResponse, error)
	mustEmbedUnimplementedFilesServer()
}

// UnimplementedFilesServer must be embedded to have forward compatible implementations.
type UnimplementedFilesServer struct {
}

func (UnimplementedFilesServer) Sync(*SyncMessage, Files_SyncServer) error {
	return status.Errorf(codes.Unimplemented, "method Sync not implemented")
}
func (UnimplementedFilesServer) List(context.Context, *ListRequest) (*ListResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method List not implemented")
}
func (UnimplementedFilesServer) GetListStream(*GetListStreamRequest, Files_GetListStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method GetListStream not implemented")
}
func (UnimplementedFilesServer) Create(context.Context, *CreateRequest) (*CreateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Create not implemented")
}
func (UnimplementedFilesServer) GetStats(context.Context, *StatsRequest) (*StatsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetStats not implemented")
}
func (UnimplementedFilesServer) StatsSession(Files_StatsSessionServer) error {
	return status.Errorf(codes.Unimplemented, "method StatsSession not implemented")
}
func (UnimplementedFilesServer) GetMeta(context.Context, *GetMetaRequest) (*GetMetaResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetMeta not implemented")
}
func (UnimplementedFilesServer) SetMeta(context.Context, *SetMetaRequest) (*SetMetaResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetMeta not implemented")
}
func (UnimplementedFilesServer) DownloadURL(context.Context, *DownloadURLRequest) (*DownloadURLResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DownloadURL not implemented")
}
func (UnimplementedFilesServer) UploadURL(context.Context, *UploadURLRequest) (*UploadURLResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UploadURL not implemented")
}
func (UnimplementedFilesServer) Copy(context.Context, *CopyRequest) (*CopyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Copy not implemented")
}
func (UnimplementedFilesServer) Move(context.Context, *MoveRequest) (*MoveResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Move not implemented")
}
func (UnimplementedFilesServer) Delete(context.Context, *DeleteRequest) (*DeleteResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Delete not implemented")
}
func (UnimplementedFilesServer) mustEmbedUnimplementedFilesServer() {}

// UnsafeFilesServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to FilesServer will
// result in compilation errors.
type UnsafeFilesServer interface {
	mustEmbedUnimplementedFilesServer()
}

func RegisterFilesServer(s grpc.ServiceRegistrar, srv FilesServer) {
	s.RegisterService(&_Files_serviceDesc, srv)
}

func _Files_Sync_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(SyncMessage)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(FilesServer).Sync(m, &filesSyncServer{stream})
}

type Files_SyncServer interface {
	Send(*Event) error
	grpc.ServerStream
}

type filesSyncServer struct {
	grpc.ServerStream
}

func (x *filesSyncServer) Send(m *Event) error {
	return x.ServerStream.SendMsg(m)
}

func _Files_List_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FilesServer).List(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Files/List",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FilesServer).List(ctx, req.(*ListRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Files_GetListStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GetListStreamRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(FilesServer).GetListStream(m, &filesGetListStreamServer{stream})
}

type Files_GetListStreamServer interface {
	Send(*Stats) error
	grpc.ServerStream
}

type filesGetListStreamServer struct {
	grpc.ServerStream
}

func (x *filesGetListStreamServer) Send(m *Stats) error {
	return x.ServerStream.SendMsg(m)
}

func _Files_Create_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FilesServer).Create(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Files/Create",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FilesServer).Create(ctx, req.(*CreateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Files_GetStats_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StatsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FilesServer).GetStats(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Files/GetStats",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FilesServer).GetStats(ctx, req.(*StatsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Files_StatsSession_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(FilesServer).StatsSession(&filesStatsSessionServer{stream})
}

type Files_StatsSessionServer interface {
	Send(*Stats) error
	Recv() (*StatsRequest, error)
	grpc.ServerStream
}

type filesStatsSessionServer struct {
	grpc.ServerStream
}

func (x *filesStatsSessionServer) Send(m *Stats) error {
	return x.ServerStream.SendMsg(m)
}

func (x *filesStatsSessionServer) Recv() (*StatsRequest, error) {
	m := new(StatsRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _Files_GetMeta_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetMetaRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FilesServer).GetMeta(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Files/GetMeta",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FilesServer).GetMeta(ctx, req.(*GetMetaRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Files_SetMeta_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetMetaRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FilesServer).SetMeta(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Files/SetMeta",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FilesServer).SetMeta(ctx, req.(*SetMetaRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Files_DownloadURL_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DownloadURLRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FilesServer).DownloadURL(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Files/DownloadURL",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FilesServer).DownloadURL(ctx, req.(*DownloadURLRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Files_UploadURL_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UploadURLRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FilesServer).UploadURL(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Files/UploadURL",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FilesServer).UploadURL(ctx, req.(*UploadURLRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Files_Copy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CopyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FilesServer).Copy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Files/Copy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FilesServer).Copy(ctx, req.(*CopyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Files_Move_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MoveRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FilesServer).Move(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Files/Move",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FilesServer).Move(ctx, req.(*MoveRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Files_Delete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FilesServer).Delete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Files/Delete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FilesServer).Delete(ctx, req.(*DeleteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Files_serviceDesc = grpc.ServiceDesc{
	ServiceName: "Files",
	HandlerType: (*FilesServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "List",
			Handler:    _Files_List_Handler,
		},
		{
			MethodName: "Create",
			Handler:    _Files_Create_Handler,
		},
		{
			MethodName: "GetStats",
			Handler:    _Files_GetStats_Handler,
		},
		{
			MethodName: "GetMeta",
			Handler:    _Files_GetMeta_Handler,
		},
		{
			MethodName: "SetMeta",
			Handler:    _Files_SetMeta_Handler,
		},
		{
			MethodName: "DownloadURL",
			Handler:    _Files_DownloadURL_Handler,
		},
		{
			MethodName: "UploadURL",
			Handler:    _Files_UploadURL_Handler,
		},
		{
			MethodName: "Copy",
			Handler:    _Files_Copy_Handler,
		},
		{
			MethodName: "Move",
			Handler:    _Files_Move_Handler,
		},
		{
			MethodName: "Delete",
			Handler:    _Files_Delete_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Sync",
			Handler:       _Files_Sync_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "GetListStream",
			Handler:       _Files_GetListStream_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "StatsSession",
			Handler:       _Files_StatsSession_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "files.proto",
}