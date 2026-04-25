package web

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"

	"yat.io/yat"
	"yat.io/yat/internal/grpcutil"
)

type Server struct {
	api *yat.Server
	cfg ServerConfig
	mux *http.ServeMux
}

type ServerConfig struct {
	Logger *slog.Logger
}

//go:embed static
var static embed.FS

func NewServer(api *yat.Server, cfg ServerConfig) *Server {
	cfg = cfg.withDefaults()
	mux := http.NewServeMux()

	static, err := fs.Sub(static, "static")
	if err != nil {
		panic(err)
	}

	mux.Handle("/", http.FileServerFS(static))

	return &Server{
		api: api,
		cfg: cfg,
		mux: mux,
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if grpcutil.IsGRPCRequest(r) {
		s.api.ServeHTTP(w, r)
		return
	}

	s.mux.ServeHTTP(w, r)
}

func (c ServerConfig) withDefaults() ServerConfig {
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}

	return c
}
