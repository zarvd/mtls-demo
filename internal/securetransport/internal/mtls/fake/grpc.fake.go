package fake

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	GRPCStubServiceName = "StubService"
	GRPCStubServicePing = "Ping"
)

type StubService interface {
	Ping(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error)
}

type stubServiceImpl struct {
}

func (s *stubServiceImpl) Ping(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func RegisterStubService(server *grpc.Server) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: GRPCStubServiceName,
		HandlerType: (*StubService)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: GRPCStubServicePing,
				Handler: func(
					srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor,
				) (any, error) {
					var in emptypb.Empty
					if err := dec(&in); err != nil {
						return nil, err
					}
					return srv.(StubService).Ping(ctx, &in)
				},
			},
		},
	}, &stubServiceImpl{})
}

func InvokePing(ctx context.Context, conn *grpc.ClientConn) (*emptypb.Empty, error) {
	var out emptypb.Empty
	method := fmt.Sprintf("/%s/%s", GRPCStubServiceName, GRPCStubServicePing)
	err := conn.Invoke(ctx, method, &emptypb.Empty{}, &out)
	return &out, err
}
