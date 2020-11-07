// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package accountspb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion7

// UsersServiceClient is the client API for UsersService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type UsersServiceClient interface {
	CreateGroup(ctx context.Context, in *CreateGroupRequest, opts ...grpc.CallOption) (*CreateGroupResponse, error)
	GetGroup(ctx context.Context, in *GetGroupRequest, opts ...grpc.CallOption) (*GetGroupResponse, error)
	StreamSubGroups(ctx context.Context, in *StreamSubGroupsRequest, opts ...grpc.CallOption) (UsersService_StreamSubGroupsClient, error)
	ListSubGroup(ctx context.Context, in *ListSubGroupRequest, opts ...grpc.CallOption) (*ListSubGroupResponse, error)
	DeleteGroup(ctx context.Context, in *DeleteGroupRequest, opts ...grpc.CallOption) (*DeleteGroupResponse, error)
	AddUser(ctx context.Context, in *AddUserRequest, opts ...grpc.CallOption) (*AddUserResponse, error)
	MoveUser(ctx context.Context, in *MoveUserRequest, opts ...grpc.CallOption) (*MoveUserResponse, error)
	GetUserStream(ctx context.Context, in *GetUserStreamRequest, opts ...grpc.CallOption) (UsersService_GetUserStreamClient, error)
	ListUsers(ctx context.Context, in *ListUsersRequest, opts ...grpc.CallOption) (*ListUsersResponse, error)
	DeleteUser(ctx context.Context, in *DeleteUserRequest, opts ...grpc.CallOption) (*DeleteUserResponse, error)
	DeleteUserSession(ctx context.Context, opts ...grpc.CallOption) (UsersService_DeleteUserSessionClient, error)
	GetUserResourcesAccessPolicyInfo(ctx context.Context, in *GetUserResourcesAccessPolicyRequest, opts ...grpc.CallOption) (*GetUserResourcesAccessPolicyResponse, error)
}

type usersServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewUsersServiceClient(cc grpc.ClientConnInterface) UsersServiceClient {
	return &usersServiceClient{cc}
}

func (c *usersServiceClient) CreateGroup(ctx context.Context, in *CreateGroupRequest, opts ...grpc.CallOption) (*CreateGroupResponse, error) {
	out := new(CreateGroupResponse)
	err := c.cc.Invoke(ctx, "/UsersService/CreateGroup", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *usersServiceClient) GetGroup(ctx context.Context, in *GetGroupRequest, opts ...grpc.CallOption) (*GetGroupResponse, error) {
	out := new(GetGroupResponse)
	err := c.cc.Invoke(ctx, "/UsersService/GetGroup", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *usersServiceClient) StreamSubGroups(ctx context.Context, in *StreamSubGroupsRequest, opts ...grpc.CallOption) (UsersService_StreamSubGroupsClient, error) {
	stream, err := c.cc.NewStream(ctx, &_UsersService_serviceDesc.Streams[0], "/UsersService/StreamSubGroups", opts...)
	if err != nil {
		return nil, err
	}
	x := &usersServiceStreamSubGroupsClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type UsersService_StreamSubGroupsClient interface {
	Recv() (*Group, error)
	grpc.ClientStream
}

type usersServiceStreamSubGroupsClient struct {
	grpc.ClientStream
}

func (x *usersServiceStreamSubGroupsClient) Recv() (*Group, error) {
	m := new(Group)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *usersServiceClient) ListSubGroup(ctx context.Context, in *ListSubGroupRequest, opts ...grpc.CallOption) (*ListSubGroupResponse, error) {
	out := new(ListSubGroupResponse)
	err := c.cc.Invoke(ctx, "/UsersService/ListSubGroup", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *usersServiceClient) DeleteGroup(ctx context.Context, in *DeleteGroupRequest, opts ...grpc.CallOption) (*DeleteGroupResponse, error) {
	out := new(DeleteGroupResponse)
	err := c.cc.Invoke(ctx, "/UsersService/DeleteGroup", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *usersServiceClient) AddUser(ctx context.Context, in *AddUserRequest, opts ...grpc.CallOption) (*AddUserResponse, error) {
	out := new(AddUserResponse)
	err := c.cc.Invoke(ctx, "/UsersService/AddUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *usersServiceClient) MoveUser(ctx context.Context, in *MoveUserRequest, opts ...grpc.CallOption) (*MoveUserResponse, error) {
	out := new(MoveUserResponse)
	err := c.cc.Invoke(ctx, "/UsersService/MoveUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *usersServiceClient) GetUserStream(ctx context.Context, in *GetUserStreamRequest, opts ...grpc.CallOption) (UsersService_GetUserStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &_UsersService_serviceDesc.Streams[1], "/UsersService/GetUserStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &usersServiceGetUserStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type UsersService_GetUserStreamClient interface {
	Recv() (*User, error)
	grpc.ClientStream
}

type usersServiceGetUserStreamClient struct {
	grpc.ClientStream
}

func (x *usersServiceGetUserStreamClient) Recv() (*User, error) {
	m := new(User)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *usersServiceClient) ListUsers(ctx context.Context, in *ListUsersRequest, opts ...grpc.CallOption) (*ListUsersResponse, error) {
	out := new(ListUsersResponse)
	err := c.cc.Invoke(ctx, "/UsersService/ListUsers", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *usersServiceClient) DeleteUser(ctx context.Context, in *DeleteUserRequest, opts ...grpc.CallOption) (*DeleteUserResponse, error) {
	out := new(DeleteUserResponse)
	err := c.cc.Invoke(ctx, "/UsersService/DeleteUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *usersServiceClient) DeleteUserSession(ctx context.Context, opts ...grpc.CallOption) (UsersService_DeleteUserSessionClient, error) {
	stream, err := c.cc.NewStream(ctx, &_UsersService_serviceDesc.Streams[2], "/UsersService/DeleteUserSession", opts...)
	if err != nil {
		return nil, err
	}
	x := &usersServiceDeleteUserSessionClient{stream}
	return x, nil
}

type UsersService_DeleteUserSessionClient interface {
	Send(*User) error
	Recv() (*User, error)
	grpc.ClientStream
}

type usersServiceDeleteUserSessionClient struct {
	grpc.ClientStream
}

func (x *usersServiceDeleteUserSessionClient) Send(m *User) error {
	return x.ClientStream.SendMsg(m)
}

func (x *usersServiceDeleteUserSessionClient) Recv() (*User, error) {
	m := new(User)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *usersServiceClient) GetUserResourcesAccessPolicyInfo(ctx context.Context, in *GetUserResourcesAccessPolicyRequest, opts ...grpc.CallOption) (*GetUserResourcesAccessPolicyResponse, error) {
	out := new(GetUserResourcesAccessPolicyResponse)
	err := c.cc.Invoke(ctx, "/UsersService/GetUserResourcesAccessPolicyInfo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UsersServiceServer is the server API for UsersService service.
// All implementations must embed UnimplementedUsersServiceServer
// for forward compatibility
type UsersServiceServer interface {
	CreateGroup(context.Context, *CreateGroupRequest) (*CreateGroupResponse, error)
	GetGroup(context.Context, *GetGroupRequest) (*GetGroupResponse, error)
	StreamSubGroups(*StreamSubGroupsRequest, UsersService_StreamSubGroupsServer) error
	ListSubGroup(context.Context, *ListSubGroupRequest) (*ListSubGroupResponse, error)
	DeleteGroup(context.Context, *DeleteGroupRequest) (*DeleteGroupResponse, error)
	AddUser(context.Context, *AddUserRequest) (*AddUserResponse, error)
	MoveUser(context.Context, *MoveUserRequest) (*MoveUserResponse, error)
	GetUserStream(*GetUserStreamRequest, UsersService_GetUserStreamServer) error
	ListUsers(context.Context, *ListUsersRequest) (*ListUsersResponse, error)
	DeleteUser(context.Context, *DeleteUserRequest) (*DeleteUserResponse, error)
	DeleteUserSession(UsersService_DeleteUserSessionServer) error
	GetUserResourcesAccessPolicyInfo(context.Context, *GetUserResourcesAccessPolicyRequest) (*GetUserResourcesAccessPolicyResponse, error)
	mustEmbedUnimplementedUsersServiceServer()
}

// UnimplementedUsersServiceServer must be embedded to have forward compatible implementations.
type UnimplementedUsersServiceServer struct {
}

func (UnimplementedUsersServiceServer) CreateGroup(context.Context, *CreateGroupRequest) (*CreateGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateGroup not implemented")
}
func (UnimplementedUsersServiceServer) GetGroup(context.Context, *GetGroupRequest) (*GetGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetGroup not implemented")
}
func (UnimplementedUsersServiceServer) StreamSubGroups(*StreamSubGroupsRequest, UsersService_StreamSubGroupsServer) error {
	return status.Errorf(codes.Unimplemented, "method StreamSubGroups not implemented")
}
func (UnimplementedUsersServiceServer) ListSubGroup(context.Context, *ListSubGroupRequest) (*ListSubGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListSubGroup not implemented")
}
func (UnimplementedUsersServiceServer) DeleteGroup(context.Context, *DeleteGroupRequest) (*DeleteGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteGroup not implemented")
}
func (UnimplementedUsersServiceServer) AddUser(context.Context, *AddUserRequest) (*AddUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddUser not implemented")
}
func (UnimplementedUsersServiceServer) MoveUser(context.Context, *MoveUserRequest) (*MoveUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method MoveUser not implemented")
}
func (UnimplementedUsersServiceServer) GetUserStream(*GetUserStreamRequest, UsersService_GetUserStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method GetUserStream not implemented")
}
func (UnimplementedUsersServiceServer) ListUsers(context.Context, *ListUsersRequest) (*ListUsersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListUsers not implemented")
}
func (UnimplementedUsersServiceServer) DeleteUser(context.Context, *DeleteUserRequest) (*DeleteUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteUser not implemented")
}
func (UnimplementedUsersServiceServer) DeleteUserSession(UsersService_DeleteUserSessionServer) error {
	return status.Errorf(codes.Unimplemented, "method DeleteUserSession not implemented")
}
func (UnimplementedUsersServiceServer) GetUserResourcesAccessPolicyInfo(context.Context, *GetUserResourcesAccessPolicyRequest) (*GetUserResourcesAccessPolicyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUserResourcesAccessPolicyInfo not implemented")
}
func (UnimplementedUsersServiceServer) mustEmbedUnimplementedUsersServiceServer() {}

// UnsafeUsersServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to UsersServiceServer will
// result in compilation errors.
type UnsafeUsersServiceServer interface {
	mustEmbedUnimplementedUsersServiceServer()
}

func RegisterUsersServiceServer(s grpc.ServiceRegistrar, srv UsersServiceServer) {
	s.RegisterService(&_UsersService_serviceDesc, srv)
}

func _UsersService_CreateGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UsersServiceServer).CreateGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/UsersService/CreateGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UsersServiceServer).CreateGroup(ctx, req.(*CreateGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UsersService_GetGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UsersServiceServer).GetGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/UsersService/GetGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UsersServiceServer).GetGroup(ctx, req.(*GetGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UsersService_StreamSubGroups_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(StreamSubGroupsRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(UsersServiceServer).StreamSubGroups(m, &usersServiceStreamSubGroupsServer{stream})
}

type UsersService_StreamSubGroupsServer interface {
	Send(*Group) error
	grpc.ServerStream
}

type usersServiceStreamSubGroupsServer struct {
	grpc.ServerStream
}

func (x *usersServiceStreamSubGroupsServer) Send(m *Group) error {
	return x.ServerStream.SendMsg(m)
}

func _UsersService_ListSubGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListSubGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UsersServiceServer).ListSubGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/UsersService/ListSubGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UsersServiceServer).ListSubGroup(ctx, req.(*ListSubGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UsersService_DeleteGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UsersServiceServer).DeleteGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/UsersService/DeleteGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UsersServiceServer).DeleteGroup(ctx, req.(*DeleteGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UsersService_AddUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UsersServiceServer).AddUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/UsersService/AddUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UsersServiceServer).AddUser(ctx, req.(*AddUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UsersService_MoveUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MoveUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UsersServiceServer).MoveUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/UsersService/MoveUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UsersServiceServer).MoveUser(ctx, req.(*MoveUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UsersService_GetUserStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GetUserStreamRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(UsersServiceServer).GetUserStream(m, &usersServiceGetUserStreamServer{stream})
}

type UsersService_GetUserStreamServer interface {
	Send(*User) error
	grpc.ServerStream
}

type usersServiceGetUserStreamServer struct {
	grpc.ServerStream
}

func (x *usersServiceGetUserStreamServer) Send(m *User) error {
	return x.ServerStream.SendMsg(m)
}

func _UsersService_ListUsers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListUsersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UsersServiceServer).ListUsers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/UsersService/ListUsers",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UsersServiceServer).ListUsers(ctx, req.(*ListUsersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UsersService_DeleteUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UsersServiceServer).DeleteUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/UsersService/DeleteUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UsersServiceServer).DeleteUser(ctx, req.(*DeleteUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UsersService_DeleteUserSession_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(UsersServiceServer).DeleteUserSession(&usersServiceDeleteUserSessionServer{stream})
}

type UsersService_DeleteUserSessionServer interface {
	Send(*User) error
	Recv() (*User, error)
	grpc.ServerStream
}

type usersServiceDeleteUserSessionServer struct {
	grpc.ServerStream
}

func (x *usersServiceDeleteUserSessionServer) Send(m *User) error {
	return x.ServerStream.SendMsg(m)
}

func (x *usersServiceDeleteUserSessionServer) Recv() (*User, error) {
	m := new(User)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _UsersService_GetUserResourcesAccessPolicyInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetUserResourcesAccessPolicyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UsersServiceServer).GetUserResourcesAccessPolicyInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/UsersService/GetUserResourcesAccessPolicyInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UsersServiceServer).GetUserResourcesAccessPolicyInfo(ctx, req.(*GetUserResourcesAccessPolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _UsersService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "UsersService",
	HandlerType: (*UsersServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateGroup",
			Handler:    _UsersService_CreateGroup_Handler,
		},
		{
			MethodName: "GetGroup",
			Handler:    _UsersService_GetGroup_Handler,
		},
		{
			MethodName: "ListSubGroup",
			Handler:    _UsersService_ListSubGroup_Handler,
		},
		{
			MethodName: "DeleteGroup",
			Handler:    _UsersService_DeleteGroup_Handler,
		},
		{
			MethodName: "AddUser",
			Handler:    _UsersService_AddUser_Handler,
		},
		{
			MethodName: "MoveUser",
			Handler:    _UsersService_MoveUser_Handler,
		},
		{
			MethodName: "ListUsers",
			Handler:    _UsersService_ListUsers_Handler,
		},
		{
			MethodName: "DeleteUser",
			Handler:    _UsersService_DeleteUser_Handler,
		},
		{
			MethodName: "GetUserResourcesAccessPolicyInfo",
			Handler:    _UsersService_GetUserResourcesAccessPolicyInfo_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamSubGroups",
			Handler:       _UsersService_StreamSubGroups_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "GetUserStream",
			Handler:       _UsersService_GetUserStream_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "DeleteUserSession",
			Handler:       _UsersService_DeleteUserSession_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "users.proto",
}
