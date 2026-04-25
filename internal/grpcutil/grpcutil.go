package grpcutil

import (
	"mime"
	"net/http"
	"strings"
)

func IsGRPCRequest(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("content-type"))
	if err != nil {
		return false
	}

	mt = strings.ToLower(mt)
	return mt == "application/grpc" ||
		strings.HasPrefix(mt, "application/grpc+proto")
}
