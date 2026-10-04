package command

import (
	"context"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/core"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

type service struct {
	UnimplementedStartupServiceServer
}

func (s *service) GetStartupInfo(ctx context.Context, request *GetStartupInfoRequest) (*StartupInfo, error) {
	info, ok := core.GetStartupInfo()
	if !ok {
		return nil, status.Error(codes.NotFound, "startup info not available")
	}
	return &StartupInfo{
		Argv:         info.Argv,
		ConfigFiles:  info.ConfigFiles,
		ConfDir:      info.ConfDir,
		ConfigFormat: info.ConfigFormat,
		Cwd:          info.Cwd,
	}, nil
}

func (s *service) Register(server *grpc.Server) {
	RegisterStartupServiceServer(server, s)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return &service{}, nil
	}))
}
