//go:build !human

package yat_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"yat.io/yat"
	"yat.io/yat/pkigen"

	msgv1 "yat.io/yat/internal/wire/msg/v1"
)

const (
	asyncTestTimeout   = 5 * time.Second
	grpcFrameHdrLen    = 5
	maxPubFrameBodyLen = (4 << 20) - 18 - 69
	testServerName     = "yat.test"
)

func TestGenRuleValidation(t *testing.T) {
	t.Run("expr_json_roundtrip", func(t *testing.T) {
		raw, err := json.Marshal(&yat.ExprCond{Match: `claims.role == "writer"`})
		if err != nil {
			t.Fatal(err)
		}

		var expr yat.ExprCond
		if err := json.Unmarshal(raw, &expr); err != nil {
			t.Fatal(err)
		}

		if expr.Match != `claims.role == "writer"` {
			t.Fatalf("expr.Match = %q", expr.Match)
		}
	})

	t.Run("invalid_rules_are_rejected", func(t *testing.T) {
		cases := []struct {
			name  string
			rules []yat.Rule
			want  string
		}{
			{
				name: "invalid_issuer",
				rules: []yat.Rule{{
					JWT: &yat.JWTCond{Issuer: "http://issuer.test"},
					Grants: []yat.Grant{{
						Paths:   []string{"auth/topic"},
						Actions: []yat.Action{yat.ActionPub},
					}},
				}},
				want: "jwt: invalid issuer",
			},
			{
				name: "malformed_issuer",
				rules: []yat.Rule{{
					JWT: &yat.JWTCond{Issuer: "https://issuer.test/%zz"},
					Grants: []yat.Grant{{
						Paths:   []string{"auth/topic"},
						Actions: []yat.Action{yat.ActionPub},
					}},
				}},
				want: "invalid URL escape",
			},
			{
				name: "invalid_expr",
				rules: []yat.Rule{{
					Expr: &yat.ExprCond{Match: `claims.role`},
					Grants: []yat.Grant{{
						Paths:   []string{"auth/topic"},
						Actions: []yat.Action{yat.ActionPub},
					}},
				}},
				want: "not a bool",
			},
			{
				name: "invalid_expr_syntax",
				rules: []yat.Rule{{
					Expr: &yat.ExprCond{Match: `claims.role ==`},
					Grants: []yat.Grant{{
						Paths:   []string{"auth/topic"},
						Actions: []yat.Action{yat.ActionPub},
					}},
				}},
				want: "Syntax error",
			},
			{
				name: "invalid_action",
				rules: []yat.Rule{{
					Grants: []yat.Grant{{
						Paths:   []string{"auth/topic"},
						Actions: []yat.Action{yat.Action("boom")},
					}},
				}},
				want: "invalid action",
			},
			{
				name: "invalid_grant_path",
				rules: []yat.Rule{{
					Grants: []yat.Grant{{
						Paths:   []string{"auth/**/topic"},
						Actions: []yat.Action{yat.ActionPub},
					}},
				}},
				want: "invalid path",
			},
			{
				name: "empty_actions",
				rules: []yat.Rule{{
					Grants: []yat.Grant{{
						Paths: []string{"auth/topic"},
					}},
				}},
				want: "empty actions",
			},
		}

		for _, tc := range cases {
			_, err := yat.NewRuleSet(context.Background(), tc.rules)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: error = %v, want substring %q", tc.name, err, tc.want)
			}
		}
	})
}

func TestGenServerProtocol(t *testing.T) {
	t.Run("new_server_requires_router", func(t *testing.T) {
		if _, err := yat.NewServer(nil, yat.ServerConfig{}); err == nil || !strings.Contains(err.Error(), "nil router") {
			t.Fatalf("NewServer(nil) error = %v", err)
		}
	})

	t.Run("servehttp_preconditions", func(t *testing.T) {
		server := newTestServer(t, yat.AllowAll())

		http1 := newGRPCRequest(http.MethodPost, msgv1.MsgService_Mpub_FullMethodName, nil)
		http1.Proto = "HTTP/1.1"
		http1.ProtoMajor = 1
		http1.ProtoMinor = 1

		method := newGRPCRequest(http.MethodGet, msgv1.MsgService_Mpub_FullMethodName, nil)
		contentType := newGRPCRequest(http.MethodPost, msgv1.MsgService_Mpub_FullMethodName, nil)
		contentType.Header.Set("content-type", "application/json")
		notFound := newGRPCRequest(http.MethodPost, "/yat.MsgService/Missing", nil)

		cases := []struct {
			name string
			req  *http.Request
			want int
		}{
			{name: "http1", req: http1, want: http.StatusHTTPVersionNotSupported},
			{name: "method", req: method, want: http.StatusMethodNotAllowed},
			{name: "content_type", req: contentType, want: http.StatusUnsupportedMediaType},
			{name: "not_found", req: notFound, want: http.StatusNotFound},
		}

		for _, tc := range cases {
			rr := httptest.NewRecorder()
			server.ServeHTTP(rr, tc.req)
			if rr.Code != tc.want {
				t.Fatalf("%s: status = %d, want %d", tc.name, rr.Code, tc.want)
			}
		}

		w := &testNoFlushWriter{header: make(http.Header)}
		server.ServeHTTP(w, newGRPCRequest(http.MethodPost, msgv1.MsgService_Mpub_FullMethodName, nil))
		if w.code != http.StatusInternalServerError {
			t.Fatalf("unflushable writer status = %d", w.code)
		}

		rr := httptest.NewRecorder()
		server.ServeHTTP(rr, method)
		if got := rr.Header().Get("allow"); got != http.MethodPost {
			t.Fatalf("allow = %q", got)
		}

		badTimeout := newGRPCRequest(http.MethodPost, msgv1.MsgService_Mpub_FullMethodName, nil)
		badTimeout.Header.Set("grpc-timeout", "tomorrow")

		rr = httptest.NewRecorder()
		server.ServeHTTP(rr, badTimeout)
		assertHTTPStatus(t, rr, http.StatusBadRequest)
	})

	t.Run("grpc_timeout_maps_context_deadline_to_deadline_exceeded", func(t *testing.T) {
		server := newTestServer(t, yat.AllowAll())
		subBody := marshalProto(t, &msgv1.SubRequest{Path: []byte("timeout/topic")})
		req := newGRPCRequest(http.MethodPost, msgv1.MsgService_Sub_FullMethodName, appendGRPCFrame(nil, subBody))
		req.Header.Set("grpc-timeout", "0n")

		rr := httptest.NewRecorder()
		server.ServeHTTP(rr, req)

		assertGRPCStatus(t, rr, codes.DeadlineExceeded)
	})

	t.Run("malformed_frames_return_expected_status_codes", func(t *testing.T) {
		server := newTestServer(t, yat.AllowAll())
		malformedBodies := []struct {
			name string
			body []byte
		}{
			{name: "compressed", body: appendGRPCHdr(nil, 0, true)},
			{name: "long", body: appendGRPCHdr(nil, 4<<20, false)},
			{name: "truncated", body: appendGRPCHdr(nil, 1, false)},
			{name: "bad_num_wire_type", body: appendGRPCFrame(nil, []byte{0x0a, 0x00})},
			{name: "bad_path_wire_type", body: appendGRPCFrame(nil, []byte{0x10, 0x00})},
		}

		for _, fullMethod := range []string{
			msgv1.MsgService_Pub_FullMethodName,
			msgv1.MsgService_Mpub_FullMethodName,
			msgv1.MsgService_Emit_FullMethodName,
		} {
			for _, tc := range malformedBodies {
				rr := httptest.NewRecorder()
				server.ServeHTTP(rr, newGRPCRequest(http.MethodPost, fullMethod, tc.body))
				assertGRPCStatus(t, rr, codes.Unknown)
			}
		}

		badSub := marshalProto(t, &msgv1.SubRequest{Path: []byte("/")})
		subCases := []struct {
			name string
			body []byte
			want codes.Code
		}{
			{name: "compressed", body: appendGRPCHdr(nil, 0, true), want: codes.Unknown},
			{name: "long", body: appendGRPCHdr(nil, 4<<20, false), want: codes.Unknown},
			{name: "truncated", body: appendGRPCHdr(nil, 1, false), want: codes.Unknown},
			{name: "bad_proto", body: appendGRPCFrame(nil, []byte{0xff}), want: codes.Unknown},
			{name: "invalid_path", body: appendGRPCFrame(nil, badSub), want: codes.InvalidArgument},
		}

		for _, tc := range subCases {
			rr := httptest.NewRecorder()
			server.ServeHTTP(rr, newGRPCRequest(http.MethodPost, msgv1.MsgService_Sub_FullMethodName, tc.body))
			assertGRPCStatus(t, rr, tc.want)
		}

		negativeLimit := int64(-1)
		postCases := []struct {
			name string
			body []byte
			want codes.Code
		}{
			{name: "compressed", body: appendGRPCHdr(nil, 0, true), want: codes.Unknown},
			{name: "long", body: appendGRPCHdr(nil, 4<<20, false), want: codes.Unknown},
			{name: "truncated", body: appendGRPCHdr(nil, 1, false), want: codes.Unknown},
			{name: "bad_path_wire_type", body: appendGRPCFrame(nil, []byte{0x10, 0x00}), want: codes.Unknown},
			{name: "invalid_path", body: appendGRPCFrame(nil, marshalProto(t, &msgv1.PostRequest{Path: []byte("/")})), want: codes.InvalidArgument},
			{name: "negative_limit", body: appendGRPCFrame(nil, marshalProto(t, &msgv1.PostRequest{
				Path:  []byte("topic"),
				Limit: &negativeLimit,
			})), want: codes.InvalidArgument},
		}

		for _, tc := range postCases {
			rr := httptest.NewRecorder()
			server.ServeHTTP(rr, newGRPCRequest(http.MethodPost, msgv1.MsgService_Post_FullMethodName, tc.body))
			assertGRPCStatus(t, rr, tc.want)
		}

		pubCases := []struct {
			name string
			req  *msgv1.PubRequest
		}{
			{name: "wild_path", req: &msgv1.PubRequest{Path: []byte("*")}},
			{name: "invalid_inbox", req: &msgv1.PubRequest{Path: []byte("topic"), Inbox: []byte("/")}},
			{name: "wild_inbox", req: &msgv1.PubRequest{Path: []byte("topic"), Inbox: []byte("*")}},
			{name: "postbox_inbox", req: &msgv1.PubRequest{Path: []byte("topic"), Inbox: []byte("@reply")}},
		}

		for _, tc := range pubCases {
			rr := httptest.NewRecorder()
			server.ServeHTTP(rr, newGRPCRequest(http.MethodPost, msgv1.MsgService_Pub_FullMethodName, appendGRPCFrame(nil, marshalProto(t, tc.req))))
			assertGRPCStatus(t, rr, codes.InvalidArgument)
		}
	})

	t.Run("oversized_data_is_invalid_argument", func(t *testing.T) {
		server := newTestServer(t, yat.AllowAll())
		data := bytes.Repeat([]byte{'x'}, yat.MaxDataLen+1)

		pubBody := marshalProto(t, &msgv1.PubRequest{
			Path: []byte("long/topic"),
			Data: data,
		})
		pubRR := httptest.NewRecorder()
		server.ServeHTTP(pubRR, newGRPCRequest(http.MethodPost, msgv1.MsgService_Pub_FullMethodName, appendGRPCFrame(nil, pubBody)))
		assertGRPCStatus(t, pubRR, codes.InvalidArgument)

		emitBody := marshalProto(t, &msgv1.EmitRequest{
			Path: []byte("long/topic"),
			Data: data,
		})
		emitRR := httptest.NewRecorder()
		server.ServeHTTP(emitRR, newGRPCRequest(http.MethodPost, msgv1.MsgService_Emit_FullMethodName, appendGRPCFrame(nil, emitBody)))
		assertGRPCStatus(t, emitRR, codes.InvalidArgument)

		ack := int64(1)
		mpubBody := marshalProto(t, &msgv1.MpubRequest{
			Ack:  &ack,
			Path: []byte("long/topic"),
			Data: data,
		})
		mpubRR := httptest.NewRecorder()
		server.ServeHTTP(mpubRR, newGRPCRequest(http.MethodPost, msgv1.MsgService_Mpub_FullMethodName, appendGRPCFrame(nil, mpubBody)))
		assertGRPCStatus(t, mpubRR, codes.OK)

		var res msgv1.MpubResponse
		bodies := grpcFrameBodies(t, mpubRR.Body.Bytes())
		if len(bodies) != 1 {
			t.Fatalf("len(mpub bodies) = %d", len(bodies))
		}
		if err := proto.Unmarshal(bodies[0], &res); err != nil {
			t.Fatal(err)
		}
		if got := codes.Code(res.GetStatus()); got != codes.InvalidArgument {
			t.Fatalf("mpub status = %v", got)
		}

		postBody := marshalProto(t, &msgv1.PostRequest{
			Path: []byte("long/topic"),
			Data: data,
		})
		postRR := httptest.NewRecorder()
		server.ServeHTTP(postRR, newGRPCRequest(http.MethodPost, msgv1.MsgService_Post_FullMethodName, appendGRPCFrame(nil, postBody)))
		assertGRPCStatus(t, postRR, codes.InvalidArgument)
	})

	t.Run("stream_frames_require_path", func(t *testing.T) {
		runSub := func(tb testing.TB, server *yat.Server, path []byte) (*blockingFlushWriter, context.CancelFunc, <-chan struct{}) {
			tb.Helper()

			subBody := marshalProto(tb, &msgv1.SubRequest{Path: path})
			ctx, cancel := context.WithCancel(context.Background())
			writer := newBlockingFlushWriter()
			done := make(chan struct{})

			go func() {
				server.ServeHTTP(writer, newGRPCRequest(http.MethodPost, msgv1.MsgService_Sub_FullMethodName, appendGRPCFrame(nil, subBody)).WithContext(ctx))
				close(done)
			}()

			<-writer.first
			return writer, cancel, done
		}

		t.Run("mpub", func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := newTestServer(t, yat.AllowAll())
				path := []byte("required/mpub")
				writer, cancel, done := runSub(t, server, path)

				ack1, ack2 := int64(1), int64(2)
				first := marshalProto(t, &msgv1.MpubRequest{
					Ack:  &ack1,
					Path: path,
					Data: []byte("ok"),
				})
				second := marshalProto(t, &msgv1.MpubRequest{
					Ack:  &ack2,
					Data: []byte("missing"),
				})

				body := appendGRPCFrame(nil, first)
				body = appendGRPCFrame(body, second)

				rr := httptest.NewRecorder()
				server.ServeHTTP(rr, newGRPCRequest(http.MethodPost, msgv1.MsgService_Mpub_FullMethodName, body))
				assertGRPCStatus(t, rr, codes.OK)

				resBodies := grpcFrameBodies(t, rr.Body.Bytes())
				if len(resBodies) != 2 {
					t.Fatalf("len(mpub bodies) = %d", len(resBodies))
				}

				var res msgv1.MpubResponse
				if err := proto.Unmarshal(resBodies[0], &res); err != nil {
					t.Fatal(err)
				}
				if got := res.GetAck(); got != ack1 {
					t.Fatalf("first ack = %d, want %d", got, ack1)
				}
				if got := codes.Code(res.GetStatus()); got != codes.OK {
					t.Fatalf("first status = %v", got)
				}

				res.Reset()
				if err := proto.Unmarshal(resBodies[1], &res); err != nil {
					t.Fatal(err)
				}
				if got := res.GetAck(); got != ack2 {
					t.Fatalf("second ack = %d, want %d", got, ack2)
				}
				if got := codes.Code(res.GetStatus()); got != codes.InvalidArgument {
					t.Fatalf("second status = %v", got)
				}

				close(writer.release)
				synctest.Wait()
				cancel()
				synctest.Wait()
				<-done

				delivered := grpcFrameBodies(t, writer.body.Bytes())
				if len(delivered) != 1 {
					t.Fatalf("len(delivered bodies) = %d", len(delivered))
				}

				var got msgv1.SubResponse
				if err := proto.Unmarshal(delivered[0], &got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.GetData(), []byte("ok")) {
					t.Fatalf("delivered data = %q", got.GetData())
				}
			})
		})

		t.Run("emit", func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := newTestServer(t, yat.AllowAll())
				path := []byte("required/emit")
				writer, cancel, done := runSub(t, server, path)

				first := marshalProto(t, &msgv1.EmitRequest{
					Path: path,
					Data: []byte("ok"),
				})
				second := marshalProto(t, &msgv1.EmitRequest{
					Data: []byte("missing"),
				})

				body := appendGRPCFrame(nil, first)
				body = appendGRPCFrame(body, second)

				rr := httptest.NewRecorder()
				server.ServeHTTP(rr, newGRPCRequest(http.MethodPost, msgv1.MsgService_Emit_FullMethodName, body))
				assertGRPCStatus(t, rr, codes.InvalidArgument)

				close(writer.release)
				synctest.Wait()
				cancel()
				synctest.Wait()
				<-done

				delivered := grpcFrameBodies(t, writer.body.Bytes())
				if len(delivered) != 1 {
					t.Fatalf("len(delivered bodies) = %d", len(delivered))
				}

				var got msgv1.SubResponse
				if err := proto.Unmarshal(delivered[0], &got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.GetData(), []byte("ok")) {
					t.Fatalf("delivered data = %q", got.GetData())
				}
			})
		})
	})

	t.Run("multiple_messages_trailing_bytes_and_permissions", func(t *testing.T) {
		allowAll := newTestServer(t, yat.AllowAll())

		subReq := marshalProto(t, &msgv1.SubRequest{Path: []byte("topic")})
		subBody := appendGRPCFrame(nil, subReq)
		subBody = appendGRPCFrame(subBody, subReq)
		subRR := httptest.NewRecorder()
		allowAll.ServeHTTP(subRR, newGRPCRequest(http.MethodPost, msgv1.MsgService_Sub_FullMethodName, subBody))
		assertGRPCStatus(t, subRR, codes.Unknown)

		pubReq := marshalProto(t, &msgv1.PubRequest{Path: []byte("topic")})
		pubBody := appendGRPCFrame(nil, pubReq)
		pubBody = appendGRPCFrame(pubBody, pubReq)
		pubRR := httptest.NewRecorder()
		allowAll.ServeHTTP(pubRR, newGRPCRequest(http.MethodPost, msgv1.MsgService_Pub_FullMethodName, pubBody))
		assertGRPCStatus(t, pubRR, codes.Unknown)

		postReq := marshalProto(t, &msgv1.PostRequest{Path: []byte("topic")})
		postBody := appendGRPCFrame(nil, postReq)
		postBody = appendGRPCFrame(postBody, postReq)
		postRR := httptest.NewRecorder()
		allowAll.ServeHTTP(postRR, newGRPCRequest(http.MethodPost, msgv1.MsgService_Post_FullMethodName, postBody))
		assertGRPCStatus(t, postRR, codes.Unknown)

		negativeLimit := int64(-1)
		negBody := marshalProto(t, &msgv1.SubRequest{
			Path:  []byte("topic"),
			Limit: &negativeLimit,
		})
		negRR := httptest.NewRecorder()
		allowAll.ServeHTTP(negRR, newGRPCRequest(http.MethodPost, msgv1.MsgService_Sub_FullMethodName, appendGRPCFrame(nil, negBody)))
		assertGRPCStatus(t, negRR, codes.InvalidArgument)

		denyAll := newTestServer(t, &yat.RuleSet{})

		authPub := marshalProto(t, &msgv1.PubRequest{Path: []byte("auth/topic")})
		authPubRR := httptest.NewRecorder()
		denyAll.ServeHTTP(authPubRR, newGRPCRequest(http.MethodPost, msgv1.MsgService_Pub_FullMethodName, appendGRPCFrame(nil, authPub)))
		assertGRPCStatus(t, authPubRR, codes.PermissionDenied)
		if authPubRR.Body.Len() != 0 {
			t.Fatalf("pub permission body length = %d", authPubRR.Body.Len())
		}

		authSub := marshalProto(t, &msgv1.SubRequest{Path: []byte("auth/topic")})
		authSubRR := httptest.NewRecorder()
		denyAll.ServeHTTP(authSubRR, newGRPCRequest(http.MethodPost, msgv1.MsgService_Sub_FullMethodName, appendGRPCFrame(nil, authSub)))
		assertHTTPStatus(t, authSubRR, http.StatusForbidden)

		badTokenReq := newGRPCRequest(http.MethodPost, msgv1.MsgService_Pub_FullMethodName, appendGRPCFrame(nil, authPub))
		badTokenReq.Header.Set("authorization", "Bearer not-a-jwt")
		badTokenRR := httptest.NewRecorder()
		denyAll.ServeHTTP(badTokenRR, badTokenReq)
		assertHTTPStatus(t, badTokenRR, http.StatusUnauthorized)

		ack := int64(1)
		mpubReq := marshalProto(t, &msgv1.MpubRequest{
			Ack:  &ack,
			Path: []byte("auth/topic"),
		})
		mpubRR := httptest.NewRecorder()
		denyAll.ServeHTTP(mpubRR, newGRPCRequest(http.MethodPost, msgv1.MsgService_Mpub_FullMethodName, appendGRPCFrame(nil, mpubReq)))
		assertGRPCStatus(t, mpubRR, codes.OK)

		var mpubRes msgv1.MpubResponse
		bodies := grpcFrameBodies(t, mpubRR.Body.Bytes())
		if len(bodies) != 1 {
			t.Fatalf("len(mpub bodies) = %d", len(bodies))
		}
		if err := proto.Unmarshal(bodies[0], &mpubRes); err != nil {
			t.Fatal(err)
		}
		if got := codes.Code(mpubRes.GetStatus()); got != codes.PermissionDenied {
			t.Fatalf("mpub permission status = %v", got)
		}

		emitReq := marshalProto(t, &msgv1.EmitRequest{Path: []byte("auth/topic")})
		emitRR := httptest.NewRecorder()
		denyAll.ServeHTTP(emitRR, newGRPCRequest(http.MethodPost, msgv1.MsgService_Emit_FullMethodName, appendGRPCFrame(nil, emitReq)))
		assertGRPCStatus(t, emitRR, codes.PermissionDenied)
		if emitRR.Body.Len() != 0 {
			t.Fatalf("emit permission body length = %d", emitRR.Body.Len())
		}
	})

	t.Run("subscription_initial_flush_and_delivery_use_synctest", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			server := newTestServer(t, yat.AllowAll())
			subBody := marshalProto(t, &msgv1.SubRequest{Path: []byte("ready/topic")})

			ctx, cancel := context.WithCancel(context.Background())
			writer := newBlockingFlushWriter()
			done := make(chan struct{})
			go func() {
				server.ServeHTTP(writer, newGRPCRequest(http.MethodPost, msgv1.MsgService_Sub_FullMethodName, appendGRPCFrame(nil, subBody)).WithContext(ctx))
				close(done)
			}()

			<-writer.first

			pubBody := marshalProto(t, &msgv1.PubRequest{
				Path: []byte("ready/topic"),
				Data: []byte("first"),
			})
			pubRR := httptest.NewRecorder()
			server.ServeHTTP(pubRR, newGRPCRequest(http.MethodPost, msgv1.MsgService_Pub_FullMethodName, appendGRPCFrame(nil, pubBody)))
			assertGRPCStatus(t, pubRR, codes.OK)

			if writer.body.Len() != 0 {
				t.Fatalf("writer buffered data before release: %d bytes", writer.body.Len())
			}

			close(writer.release)
			synctest.Wait()

			bodies := grpcFrameBodies(t, writer.body.Bytes())
			if len(bodies) != 1 {
				t.Fatalf("len(delivered bodies) = %d", len(bodies))
			}

			var got msgv1.SubResponse
			if err := proto.Unmarshal(bodies[0], &got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.GetData(), []byte("first")) {
				t.Fatalf("delivered data = %q", got.GetData())
			}

			cancel()
			synctest.Wait()
			<-done
		})
	})

	t.Run("limited_subscription_finishes_even_if_final_delivery_is_dropped", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			server := newTestServer(t, yat.AllowAll())
			limit := int64(2)
			subBody := marshalProto(t, &msgv1.SubRequest{
				Path:  []byte("limit/topic"),
				Limit: &limit,
			})

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			writer := newBlockingFlushWriter()
			done := make(chan struct{})
			go func() {
				server.ServeHTTP(writer, newGRPCRequest(http.MethodPost, msgv1.MsgService_Sub_FullMethodName, appendGRPCFrame(nil, subBody)).WithContext(ctx))
				close(done)
			}()

			<-writer.first

			dataLen := maxPayloadLen(t, yat.MaxDataLen, func(n int) bool {
				req := &msgv1.MpubRequest{
					Path: []byte("limit/topic"),
					Data: make([]byte, n),
				}
				return proto.Size(req) <= maxPubFrameBodyLen
			})

			first := marshalProto(t, &msgv1.MpubRequest{
				Path: []byte("limit/topic"),
				Data: bytes.Repeat([]byte{0x11}, dataLen),
			})
			second := marshalProto(t, &msgv1.MpubRequest{
				Path: []byte("limit/topic"),
				Data: bytes.Repeat([]byte{0x22}, dataLen),
			})

			mpubBody := appendGRPCFrame(nil, first)
			mpubBody = appendGRPCFrame(mpubBody, second)

			mpubRR := httptest.NewRecorder()
			server.ServeHTTP(mpubRR, newGRPCRequest(http.MethodPost, msgv1.MsgService_Mpub_FullMethodName, mpubBody))
			assertGRPCStatus(t, mpubRR, codes.OK)

			close(writer.release)
			synctest.Wait()
			<-done

			assertGRPCHeaderStatus(t, writer.code, writer.header, codes.OK)
			bodies := grpcFrameBodies(t, writer.body.Bytes())
			if len(bodies) != 1 {
				t.Fatalf("len(delivered bodies) = %d", len(bodies))
			}

			var got msgv1.SubResponse
			if err := proto.Unmarshal(bodies[0], &got); err != nil {
				t.Fatal(err)
			}
			if len(got.GetData()) != dataLen || got.GetData()[0] != 0x11 || got.GetData()[len(got.GetData())-1] != 0x11 {
				t.Fatal("unexpected delivered payload")
			}
		})
	})
}

func TestGenClientServer(t *testing.T) {
	t.Run("tls_roundtrip_wildcards_and_ids", func(t *testing.T) {
		endpoint := startTLSEndpoint(t, yat.AllowAll())
		defer endpoint.Close()

		pub := newTLSClient(t, endpoint)
		exact := newTLSClient(t, endpoint)
		elem := newTLSClient(t, endpoint)
		suffix := newTLSClient(t, endpoint)
		defer closeClient(t, pub)
		defer closeClient(t, exact)
		defer closeClient(t, elem)
		defer closeClient(t, suffix)

		path := yat.NewPath("fanout/topic")
		deep := yat.NewPath("fanout/topic/deep")
		reply := yat.NewPath("reply/system")

		exactProbe := newSubProbe(t, exact, yat.Sel{Path: path})
		elemProbe := newSubProbe(t, elem, yat.Sel{Path: yat.NewPath("fanout/*")})
		suffixProbe := newSubProbe(t, suffix, yat.Sel{Path: yat.NewPath("fanout/**")})
		defer exactProbe.Cancel(t)
		defer elemProbe.Cancel(t)
		defer suffixProbe.Cancel(t)

		if err := pub.Publish(context.Background(), yat.Msg{
			Path:  path,
			Inbox: reply,
			Data:  []byte("exact"),
		}); err != nil {
			t.Fatal(err)
		}
		if err := pub.Publish(context.Background(), yat.Msg{
			Path: deep,
			Data: []byte("deep"),
		}); err != nil {
			t.Fatal(err)
		}

		assertMsg(t, receiveMsg(t, exactProbe.msgs), path, reply, []byte("exact"))
		assertMsg(t, receiveMsg(t, elemProbe.msgs), path, reply, []byte("exact"))

		got := receiveMsgs(t, suffixProbe.msgs, 2)
		seenIDs := make(map[yat.MsgID]struct{}, len(got))
		for _, msg := range got {
			if msg.ID() == (yat.MsgID{}) {
				t.Fatal("got zero message id")
			}
			if _, ok := seenIDs[msg.ID()]; ok {
				t.Fatal("message ids were reused")
			}
			seenIDs[msg.ID()] = struct{}{}
		}
		got = assertContainsMsg(t, got, path, reply, []byte("exact"))
		got = assertContainsMsg(t, got, deep, yat.Path{}, []byte("deep"))
		if len(got) != 0 {
			t.Fatalf("unexpected extra messages: %+v", got)
		}
	})

	t.Run("tls_publish_stream_emit_and_near_max_payload", func(t *testing.T) {
		endpoint := startTLSEndpoint(t, yat.AllowAll())
		defer endpoint.Close()

		pub := newTLSClient(t, endpoint)
		subc := newTLSClient(t, endpoint)
		defer closeClient(t, pub)
		defer closeClient(t, subc)

		path := yat.NewPath("stream/topic")
		probe := newSubProbe(t, subc, yat.Sel{Path: path})
		defer probe.Cancel(t)

		stream := mustNewPublisher(t, pub, context.Background())
		if err := stream.Publish(context.Background(), yat.Msg{
			Path:  path,
			Inbox: yat.NewPath("reply/stream-1"),
			Data:  []byte("stream-1"),
		}); err != nil {
			t.Fatal(err)
		}

		reply2 := yat.NewPath("reply/stream-2")
		payload := nearMaxMpubData(t, path, reply2)
		if err := stream.Publish(context.Background(), yat.Msg{
			Path:  path,
			Inbox: reply2,
			Data:  payload,
		}); err != nil {
			t.Fatal(err)
		}

		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}

		assertErrContains(t, stream.Publish(context.Background(), yat.Msg{Path: path, Data: []byte("after-close")}), "publisher closed")

		emitter := mustNewEmitter(t, pub, context.Background())
		if err := emitter.Emit(yat.Msg{
			Path:  path,
			Inbox: yat.NewPath("reply/emit-1"),
			Data:  []byte("emit-1"),
		}); err != nil {
			t.Fatal(err)
		}
		if err := emitter.Emit(yat.Msg{
			Path:  path,
			Inbox: yat.NewPath("reply/emit-2"),
			Data:  []byte("emit-2"),
		}); err != nil {
			t.Fatal(err)
		}

		if err := emitter.Close(); err != nil {
			t.Fatal(err)
		}

		assertErrContains(t, emitter.Emit(yat.Msg{Path: path, Data: []byte("after-close")}), "emitter closed")

		got := receiveMsgs(t, probe.msgs, 4)
		got = assertContainsMsg(t, got, path, yat.NewPath("reply/stream-1"), []byte("stream-1"))
		got = assertContainsMsg(t, got, path, reply2, payload)
		got = assertContainsMsg(t, got, path, yat.NewPath("reply/emit-1"), []byte("emit-1"))
		got = assertContainsMsg(t, got, path, yat.NewPath("reply/emit-2"), []byte("emit-2"))
		if len(got) != 0 {
			t.Fatalf("unexpected extra messages: %+v", got)
		}
	})

	t.Run("insecure_h2c_roundtrip", func(t *testing.T) {
		target, cleanup := startH2CEndpoint(t, yat.AllowAll())
		defer cleanup()

		pub := newInsecureClient(t, target)
		subc := newInsecureClient(t, target)
		defer closeClient(t, pub)
		defer closeClient(t, subc)

		path := yat.NewPath("insecure/topic")
		probe := newSubProbe(t, subc, yat.Sel{Path: path})
		defer probe.Cancel(t)

		if err := pub.Publish(context.Background(), yat.Msg{
			Path:  path,
			Inbox: yat.NewPath("reply/insecure"),
			Data:  []byte("hello"),
		}); err != nil {
			t.Fatal(err)
		}

		assertMsg(t, receiveMsg(t, probe.msgs), path, yat.NewPath("reply/insecure"), []byte("hello"))
	})

	t.Run("post_handle_roundtrip_limits_and_errors", func(t *testing.T) {
		endpoint := startTLSEndpoint(t, yat.AllowAll())
		defer endpoint.Close()

		poster := newTLSClient(t, endpoint)
		handler1 := newTLSClient(t, endpoint)
		handler2 := newTLSClient(t, endpoint)
		observer := newTLSClient(t, endpoint)
		defer closeClient(t, poster)
		defer closeClient(t, handler1)
		defer closeClient(t, handler2)
		defer closeClient(t, observer)

		noHandlerPath := yat.NewPath("post/no-handler")
		observerProbe := newSubProbe(t, observer, yat.Sel{Path: noHandlerPath})
		defer observerProbe.Cancel(t)

		assertStatusCode(t, poster.Post(context.Background(), yat.Req{
			Path: noHandlerPath,
			Data: []byte("no-handler"),
		}, func(yat.Res) error {
			t.Fatal("unexpected post response")
			return nil
		}), codes.Unavailable)

		path := yat.NewPath("post/topic")
		postProbe := newSubProbe(t, observer, yat.Sel{Path: path})
		defer postProbe.Cancel(t)

		h1Reqs := make(chan handledReq, 2)
		h1Ctx, cancelH1 := context.WithCancel(context.Background())
		h1, err := handler1.Handle(h1Ctx, yat.Sel{Path: path}, func(ctx context.Context, gotPath yat.Path, in []byte) []byte {
			h1Reqs <- handledReq{
				path: gotPath,
				data: bytes.Clone(in),
				err:  ctx.Err(),
			}
			return append([]byte("one:"), in...)
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cancelSub(t, cancelH1, h1)

		h2Reqs := make(chan handledReq, 2)
		h2Ctx, cancelH2 := context.WithCancel(context.Background())
		h2, err := handler2.Handle(h2Ctx, yat.Sel{Path: path}, func(ctx context.Context, gotPath yat.Path, in []byte) []byte {
			h2Reqs <- handledReq{
				path: gotPath,
				data: bytes.Clone(in),
				err:  ctx.Err(),
			}
			return append([]byte("two:"), in...)
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cancelSub(t, cancelH2, h2)

		var got []yat.Res
		if err := poster.Post(context.Background(), yat.Req{
			Path:  path,
			Data:  []byte("request"),
			Limit: 2,
		}, func(res yat.Res) error {
			got = append(got, res)
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		if len(got) != 2 {
			t.Fatalf("len(post responses) = %d", len(got))
		}
		got = assertContainsRes(t, got, yat.Path{}, []byte("one:request"))
		got = assertContainsRes(t, got, yat.Path{}, []byte("two:request"))
		if len(got) != 0 {
			t.Fatalf("unexpected extra responses: %+v", got)
		}

		postMsg := receiveMsg(t, postProbe.msgs)
		if !postMsg.Inbox.IsPostbox() {
			t.Fatalf("post inbox = %q, want postbox", postMsg.Inbox.String())
		}
		assertMsg(t, postMsg, path, postMsg.Inbox, []byte("request"))
		if postMsg.ID() == (yat.MsgID{}) {
			t.Fatal("post message id is zero")
		}

		assertHandledReq(t, receiveHandledReq(t, h1Reqs), path, []byte("request"))
		assertHandledReq(t, receiveHandledReq(t, h2Reqs), path, []byte("request"))

		got = nil
		limitCtx, cancelLimit := context.WithTimeout(context.Background(), asyncTestTimeout)
		defer cancelLimit()
		if err := poster.Post(limitCtx, yat.Req{
			Path:  path,
			Data:  []byte("limited"),
			Limit: 1,
		}, func(res yat.Res) error {
			got = append(got, res)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("len(limited post responses) = %d", len(got))
		}
		if !got[0].Inbox.IsZero() {
			t.Fatalf("limited response inbox = %q, want empty", got[0].Inbox.String())
		}
		if !bytes.Equal(got[0].Data, []byte("one:limited")) && !bytes.Equal(got[0].Data, []byte("two:limited")) {
			t.Fatalf("limited response data = %q", got[0].Data)
		}

		oneShotPath := yat.NewPath("post/one-shot")
		oneShotReqs := make(chan handledReq, 1)
		oneShotCtx, cancelOneShot := context.WithCancel(context.Background())
		oneShot, err := handler1.Handle(oneShotCtx, yat.Sel{
			Path:  oneShotPath,
			Limit: 1,
		}, func(ctx context.Context, gotPath yat.Path, in []byte) []byte {
			oneShotReqs <- handledReq{
				path: gotPath,
				data: bytes.Clone(in),
				err:  ctx.Err(),
			}
			return append([]byte("one-shot:"), in...)
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cancelSub(t, cancelOneShot, oneShot)

		got = nil
		oneShotPostCtx, cancelOneShotPost := context.WithTimeout(context.Background(), asyncTestTimeout)
		defer cancelOneShotPost()
		if err := poster.Post(oneShotPostCtx, yat.Req{
			Path:  oneShotPath,
			Data:  []byte("request"),
			Limit: 1,
		}, func(res yat.Res) error {
			got = append(got, res)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("len(one-shot post responses) = %d", len(got))
		}
		assertContainsRes(t, got, yat.Path{}, []byte("one-shot:request"))
		waitSubDone(t, oneShot)
		assertHandledReq(t, receiveHandledReq(t, oneShotReqs), oneShotPath, []byte("request"))

		concurrentPath := yat.NewPath("post/concurrent")
		concurrentStarts := make(chan []byte, 2)
		concurrentRelease := make(chan struct{})
		concurrentCtx, cancelConcurrent := context.WithCancel(context.Background())
		concurrent, err := handler1.Handle(concurrentCtx, yat.Sel{Path: concurrentPath}, func(_ context.Context, _ yat.Path, in []byte) []byte {
			concurrentStarts <- bytes.Clone(in)
			<-concurrentRelease
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cancelSub(t, cancelConcurrent, concurrent)
		defer close(concurrentRelease)

		if err := poster.Publish(context.Background(), yat.Msg{
			Path:  concurrentPath,
			Inbox: yat.NewPath("reply/concurrent"),
			Data:  []byte("first"),
		}); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-concurrentStarts:
			if !bytes.Equal(got, []byte("first")) {
				t.Fatalf("first concurrent data = %q", got)
			}
		case <-time.After(asyncTestTimeout):
			t.Fatal("timed out waiting for first concurrent handler")
		}

		if err := poster.Publish(context.Background(), yat.Msg{
			Path:  concurrentPath,
			Inbox: yat.NewPath("reply/concurrent"),
			Data:  []byte("second"),
		}); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-concurrentStarts:
			if !bytes.Equal(got, []byte("second")) {
				t.Fatalf("second concurrent data = %q", got)
			}
		case <-time.After(asyncTestTimeout):
			t.Fatal("timed out waiting for second concurrent handler")
		}

		callbackErr := errors.New("post callback stopped")
		if err := poster.Post(context.Background(), yat.Req{
			Path: path,
			Data: []byte("callback-error"),
		}, func(yat.Res) error {
			return callbackErr
		}); !errors.Is(err, callbackErr) {
			t.Fatalf("Post(callback error) = %v, want %v", err, callbackErr)
		}
	})

	t.Run("handle_wildcard_replies_to_publish_inbox_and_post", func(t *testing.T) {
		endpoint := startTLSEndpoint(t, yat.AllowAll())
		defer endpoint.Close()

		requester := newTLSClient(t, endpoint)
		handler := newTLSClient(t, endpoint)
		replySub := newTLSClient(t, endpoint)
		defer closeClient(t, requester)
		defer closeClient(t, handler)
		defer closeClient(t, replySub)

		path := yat.NewPath("handle/manual")
		reply := yat.NewPath("reply/handle-manual")

		replyProbe := newSubProbe(t, replySub, yat.Sel{Path: reply})
		defer replyProbe.Cancel(t)

		handled := make(chan handledReq, 2)
		hctx, cancelHandle := context.WithCancel(context.Background())
		hsub, err := handler.Handle(hctx, yat.Sel{Path: yat.NewPath("handle/*")}, func(ctx context.Context, gotPath yat.Path, in []byte) []byte {
			handled <- handledReq{
				path: gotPath,
				data: bytes.Clone(in),
				err:  ctx.Err(),
			}
			return append([]byte("handled:"), in...)
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cancelSub(t, cancelHandle, hsub)

		if err := requester.Publish(context.Background(), yat.Msg{
			Path:  path,
			Inbox: reply,
			Data:  []byte("manual"),
		}); err != nil {
			t.Fatal(err)
		}

		assertMsg(t, receiveMsg(t, replyProbe.msgs), reply, yat.Path{}, []byte("handled:manual"))
		assertHandledReq(t, receiveHandledReq(t, handled), path, []byte("manual"))

		postCtx, cancelPost := context.WithTimeout(context.Background(), asyncTestTimeout)
		defer cancelPost()

		var got []yat.Res
		if err := requester.Post(postCtx, yat.Req{
			Path:  path,
			Data:  []byte("post"),
			Limit: 1,
		}, func(res yat.Res) error {
			got = append(got, res)
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		if len(got) != 1 {
			t.Fatalf("len(post responses) = %d", len(got))
		}
		got = assertContainsRes(t, got, yat.Path{}, []byte("handled:post"))
		if len(got) != 0 {
			t.Fatalf("unexpected extra responses: %+v", got)
		}
		assertHandledReq(t, receiveHandledReq(t, handled), path, []byte("post"))

		unlimitedCtx, cancelUnlimited := context.WithTimeout(context.Background(), asyncTestTimeout)
		defer cancelUnlimited()

		got = nil
		err = requester.Post(unlimitedCtx, yat.Req{
			Path: path,
			Data: []byte("unlimited"),
		}, func(res yat.Res) error {
			got = append(got, res)
			cancelUnlimited()
			return nil
		})
		if err == nil || (!errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled) {
			t.Fatalf("Post(cancel after unlimited response) = %v", err)
		}

		if len(got) != 1 {
			t.Fatalf("len(unlimited post responses) = %d", len(got))
		}
		got = assertContainsRes(t, got, yat.Path{}, []byte("handled:unlimited"))
		if len(got) != 0 {
			t.Fatalf("unexpected extra responses: %+v", got)
		}
		assertHandledReq(t, receiveHandledReq(t, handled), path, []byte("unlimited"))
	})

	t.Run("subscription_stop_is_safe_and_client_close_blocks_future_operations", func(t *testing.T) {
		endpoint := startTLSEndpoint(t, yat.AllowAll())
		defer endpoint.Close()

		path := yat.NewPath("life/topic")

		pub := newTLSClient(t, endpoint)
		subc := newTLSClient(t, endpoint)
		defer closeClient(t, pub)

		probe := newSubProbe(t, subc, yat.Sel{Path: path})
		probe.Cancel(t)

		if err := subc.Close(); err != nil {
			t.Fatal(err)
		}

		if err := subc.Publish(context.Background(), yat.Msg{Path: path}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Publish(after close) = %v", err)
		}
		if _, err := subc.Subscribe(context.Background(), yat.Sel{Path: path}, func(context.Context, yat.Msg) {}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Subscribe(after close) = %v", err)
		}
		if err := subc.Post(context.Background(), yat.Req{Path: path}, func(yat.Res) error { return nil }); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Post(after close) = %v", err)
		}
		if _, err := subc.Handle(context.Background(), yat.Sel{Path: path}, func(context.Context, yat.Path, []byte) []byte { return nil }); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Handle(after close) = %v", err)
		}
		if _, err := subc.NewPublisher(context.Background()); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("NewPublisher(after close) = %v", err)
		}
		if _, err := subc.NewEmitter(context.Background()); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("NewEmitter(after close) = %v", err)
		}
	})

	t.Run("validation_and_client_lifecycle", func(t *testing.T) {
		endpoint := startTLSEndpoint(t, yat.AllowAll())
		defer endpoint.Close()

		path := yat.NewPath("validate/topic")
		client := newTLSClient(t, endpoint)

		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := client.Publish(canceledCtx, yat.Msg{Path: path}); !errors.Is(err, context.Canceled) {
			t.Fatalf("Publish(cancelled) = %v", err)
		}
		if err := client.Post(canceledCtx, yat.Req{Path: path}, func(yat.Res) error { return nil }); !errors.Is(err, context.Canceled) {
			t.Fatalf("Post(cancelled) = %v", err)
		}

		msgCases := []struct {
			name string
			msg  yat.Msg
			want string
		}{
			{name: "empty_path", msg: yat.Msg{}, want: "empty path"},
			{name: "wild_path", msg: yat.Msg{Path: yat.NewPath("*")}, want: "wild path"},
			{name: "wild_inbox", msg: yat.Msg{Path: path, Inbox: yat.NewPath("*")}, want: "wild inbox path"},
			{name: "postbox_inbox", msg: yat.Msg{Path: path, Inbox: yat.NewPath("@reply")}, want: "invalid postbox"},
			{name: "long_data", msg: yat.Msg{Path: path, Data: make([]byte, yat.MaxDataLen+1)}, want: "long data"},
		}

		for _, tc := range msgCases {
			assertErrContains(t, client.Publish(context.Background(), tc.msg), tc.want)
		}

		assertErrContains(t, func() error {
			_, err := client.Subscribe(context.Background(), yat.Sel{}, func(context.Context, yat.Msg) {})
			return err
		}(), "empty path")

		assertErrContains(t, func() error {
			_, err := client.Subscribe(context.Background(), yat.Sel{Path: yat.NewPath("@reply")}, func(context.Context, yat.Msg) {})
			return err
		}(), "invalid postbox")

		_, err := client.Subscribe(context.Background(), yat.Sel{Path: path}, nil)
		assertErrContains(t, err, "nil func")

		assertErrContains(t, client.Post(context.Background(), yat.Req{Path: path}, nil), "nil func")
		if _, err := client.Handle(context.Background(), yat.Sel{Path: path}, nil); err == nil || !strings.Contains(err.Error(), "nil func") {
			t.Fatalf("Handle(nil func) = %v", err)
		}

		reqCases := []struct {
			name string
			req  yat.Req
			want string
		}{
			{name: "empty_path", req: yat.Req{}, want: "empty path"},
			{name: "wild_path", req: yat.Req{Path: yat.NewPath("*")}, want: "wild path"},
			{name: "long_data", req: yat.Req{Path: path, Data: make([]byte, yat.MaxDataLen+1)}, want: "long data"},
			{name: "negative_limit", req: yat.Req{Path: path, Limit: -1}, want: "negative limit"},
		}

		for _, tc := range reqCases {
			assertErrContains(t, client.Post(context.Background(), tc.req, func(yat.Res) error { return nil }), tc.want)
		}

		assertErrContains(t, func() error {
			_, err := client.Handle(context.Background(), yat.Sel{}, func(context.Context, yat.Path, []byte) []byte { return nil })
			return err
		}(), "empty path")

		if _, err := yat.NewClient("example.test:443", yat.ClientConfig{
			TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: "token",
				TokenType:   "Bearer",
			}),
		}); err == nil || !strings.Contains(err.Error(), "token source requires tls") {
			t.Fatalf("NewClient(token-without-tls) = %v", err)
		}

		publisher := mustNewPublisher(t, client, context.Background())
		pubCtx, cancelPub := context.WithCancel(context.Background())
		cancelPub()
		if err := publisher.Publish(pubCtx, yat.Msg{Path: path, Data: []byte("cancelled")}); !errors.Is(err, context.Canceled) {
			t.Fatalf("PublishStream.Publish(cancelled) = %v", err)
		}

		emitter := mustNewEmitter(t, client, context.Background())
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}

		if err := publisher.Publish(context.Background(), yat.Msg{Path: path, Data: []byte("after-close")}); err == nil {
			t.Fatal("PublishStream.Publish(after client close) unexpectedly succeeded")
		}
		if err := emitter.Emit(yat.Msg{Path: path, Data: []byte("after-close")}); err == nil {
			t.Fatal("EmitStream.Emit(after client close) unexpectedly succeeded")
		}
	})
}

func TestGenAuthGrantPathMatching(t *testing.T) {
	rules := []yat.Rule{{
		Grants: []yat.Grant{
			{
				Paths: []string{
					"match/exact",
					"match/elem/*",
					"match/suffix/**",
					"match/short/one/two",
				},
				Actions: []yat.Action{yat.ActionPub},
			},
			{
				Paths:   []string{"match/**"},
				Actions: []yat.Action{yat.ActionSub},
			},
		},
	}}

	endpoint := startTLSEndpoint(t, mustRuleSet(t, context.Background(), rules))
	defer endpoint.Close()

	publisher := newTLSClient(t, endpoint)
	subscriber := newTLSClient(t, endpoint)
	defer closeClient(t, publisher)
	defer closeClient(t, subscriber)

	probe := newSubProbe(t, subscriber, yat.Sel{Path: yat.NewPath("match/**")})
	defer probe.Cancel(t)

	allowed := []struct {
		path yat.Path
		data []byte
	}{
		{path: yat.NewPath("match/exact"), data: []byte("exact")},
		{path: yat.NewPath("match/elem/leaf"), data: []byte("elem")},
		{path: yat.NewPath("match/suffix/deep/leaf"), data: []byte("suffix")},
	}

	for _, msg := range allowed {
		if err := publisher.Publish(context.Background(), yat.Msg{
			Path: msg.path,
			Data: msg.data,
		}); err != nil {
			t.Fatal(err)
		}
	}

	got := receiveMsgs(t, probe.msgs, len(allowed))
	for _, msg := range allowed {
		got = assertContainsMsg(t, got, msg.path, yat.Path{}, msg.data)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected extra messages: %+v", got)
	}

	denied := []yat.Path{
		yat.NewPath("match/elem/leaf/extra"),
		yat.NewPath("match/short/one"),
		yat.NewPath("match/other"),
	}

	for _, path := range denied {
		assertStatusCode(t, publisher.Publish(context.Background(), yat.Msg{
			Path: path,
			Data: []byte("denied"),
		}), codes.PermissionDenied)
	}
}

func TestGenAuthWildcardGrantDoesNotMatchWildcardSelector(t *testing.T) {
	rules := []yat.Rule{{
		Grants: []yat.Grant{{
			Paths:   []string{"test/*"},
			Actions: []yat.Action{yat.ActionSub},
		}},
	}}

	endpoint := startTLSEndpoint(t, mustRuleSet(t, context.Background(), rules))
	defer endpoint.Close()

	client := newTLSClient(t, endpoint)
	defer closeClient(t, client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub, err := client.Subscribe(ctx, yat.Sel{Path: yat.NewPath("test/**")}, func(context.Context, yat.Msg) {})
	if err == nil {
		cancelSub(t, cancel, sub)
		t.Fatal(`"test/*" grant allowed "test/**" selector`)
	}

	assertStatusCode(t, err, codes.PermissionDenied)
}

func TestGenAuthJWT(t *testing.T) {
	issuer := newAuthIssuer(t)
	path := yat.NewPath("auth/topic")
	altPath := yat.NewPath("auth/alt/topic")
	reply := yat.NewPath("reply/writer")

	rules := []yat.Rule{
		{
			JWT: authJWTCond(issuer.url, "yat-client", "writer*"),
			Expr: &yat.ExprCond{
				Match: `claims.role == "writer"`,
			},
			Grants: []yat.Grant{{
				Paths:   []string{path.String(), altPath.String()},
				Actions: []yat.Action{yat.ActionPub},
			}},
		},
		{
			JWT: authJWTCond(issuer.url, "yat-client", "writer*"),
			Expr: &yat.ExprCond{
				Match: `claims.reply == true`,
			},
			Grants: []yat.Grant{{
				Paths:   []string{"reply/**"},
				Actions: []yat.Action{yat.ActionSub},
			}},
		},
		{
			JWT: authJWTCond(issuer.url, "yat-client", "reader"),
			Expr: &yat.ExprCond{
				Match: `claims.role == "reader"`,
			},
			Grants: []yat.Grant{{
				Paths:   []string{path.String(), altPath.String()},
				Actions: []yat.Action{yat.ActionSub},
			}},
		},
	}

	endpoint := startTLSEndpoint(t, mustRuleSet(t, issuer.context(), rules))
	defer endpoint.Close()

	writerToken := func(tb testing.TB) *oauth2.Token {
		tb.Helper()
		return issuer.token(tb, authTokenSpec{
			Subject:  "writer-1",
			Audience: []string{"yat-client", "other-client"},
			Claims: map[string]any{
				"role":  "writer",
				"reply": true,
			},
		})
	}

	writerNoReplyToken := func(tb testing.TB) *oauth2.Token {
		tb.Helper()
		return issuer.token(tb, authTokenSpec{
			Subject:  "writer-2",
			Audience: []string{"yat-client"},
			Claims: map[string]any{
				"role":  "writer",
				"reply": false,
			},
		})
	}

	readerToken := func(tb testing.TB) *oauth2.Token {
		tb.Helper()
		return issuer.token(tb, authTokenSpec{
			Subject:  "reader",
			Audience: []string{"yat-client"},
			Claims: map[string]any{
				"role": "reader",
			},
		})
	}

	t.Run("writer_reader_roundtrip", func(t *testing.T) {
		writer := newAuthClient(t, endpoint, writerToken(t))
		reader := newAuthClient(t, endpoint, readerToken(t))
		defer closeClient(t, writer)
		defer closeClient(t, reader)

		probe := newSubProbe(t, reader, yat.Sel{Path: path})
		defer probe.Cancel(t)

		if err := writer.Publish(context.Background(), yat.Msg{
			Path:  path,
			Inbox: reply,
			Data:  []byte("jwt-pub"),
		}); err != nil {
			t.Fatal(err)
		}

		emitter := mustNewEmitter(t, writer, context.Background())
		if err := emitter.Emit(yat.Msg{
			Path:  path,
			Inbox: reply,
			Data:  []byte("jwt-emit"),
		}); err != nil {
			t.Fatal(err)
		}
		if err := emitter.Close(); err != nil {
			t.Fatal(err)
		}

		got := receiveMsgs(t, probe.msgs, 2)
		got = assertContainsMsg(t, got, path, reply, []byte("jwt-pub"))
		got = assertContainsMsg(t, got, path, reply, []byte("jwt-emit"))
		if len(got) != 0 {
			t.Fatalf("unexpected extra messages: %+v", got)
		}
	})

	t.Run("post_handle_uses_postbox_auth", func(t *testing.T) {
		poster := newAuthClient(t, endpoint, writerNoReplyToken(t))
		handler := newAuthClient(t, endpoint, readerToken(t))
		defer closeClient(t, poster)
		defer closeClient(t, handler)

		hctx, cancelHandle := context.WithCancel(context.Background())
		hsub, err := handler.Handle(hctx, yat.Sel{Path: path}, func(_ context.Context, gotPath yat.Path, in []byte) []byte {
			if !gotPath.Equal(path) {
				return []byte("wrong-path")
			}
			return append([]byte("handled:"), in...)
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cancelSub(t, cancelHandle, hsub)

		ctx, cancel := context.WithTimeout(context.Background(), asyncTestTimeout)
		defer cancel()

		var got []yat.Res
		if err := poster.Post(ctx, yat.Req{
			Path:  path,
			Data:  []byte("jwt-post"),
			Limit: 1,
		}, func(res yat.Res) error {
			got = append(got, res)
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		if len(got) != 1 {
			t.Fatalf("len(post responses) = %d", len(got))
		}
		got = assertContainsRes(t, got, yat.Path{}, []byte("handled:jwt-post"))
		if len(got) != 0 {
			t.Fatalf("unexpected extra responses: %+v", got)
		}
	})

	t.Run("single_grant_matches_multiple_paths", func(t *testing.T) {
		writer := newAuthClient(t, endpoint, writerNoReplyToken(t))
		reader := newAuthClient(t, endpoint, readerToken(t))
		defer closeClient(t, writer)
		defer closeClient(t, reader)

		probe := newSubProbe(t, reader, yat.Sel{Path: altPath})
		defer probe.Cancel(t)

		if err := writer.Publish(context.Background(), yat.Msg{
			Path: altPath,
			Data: []byte("jwt-alt"),
		}); err != nil {
			t.Fatal(err)
		}

		assertMsg(t, receiveMsg(t, probe.msgs), altPath, yat.Path{}, []byte("jwt-alt"))
	})

	t.Run("permission_denials_surface_consistently", func(t *testing.T) {
		anonymous := newTLSClient(t, endpoint)
		defer closeClient(t, anonymous)
		assertStatusCode(t, anonymous.Publish(context.Background(), yat.Msg{Path: path, Data: []byte("anon")}), codes.PermissionDenied)
		assertStatusCode(t, anonymous.Post(context.Background(), yat.Req{Path: path}, func(yat.Res) error { return nil }), codes.PermissionDenied)

		wrongAudience := newAuthClient(t, endpoint, issuer.token(t, authTokenSpec{
			Subject:  "writer-3",
			Audience: []string{"other-client"},
			Claims: map[string]any{
				"role":  "writer",
				"reply": true,
			},
		}))
		defer closeClient(t, wrongAudience)
		assertStatusCode(t, wrongAudience.Publish(context.Background(), yat.Msg{Path: path, Data: []byte("wrong-aud")}), codes.PermissionDenied)

		malformed := newAuthClient(t, endpoint, &oauth2.Token{
			AccessToken: "not-a-jwt",
			TokenType:   "Bearer",
		})
		defer closeClient(t, malformed)
		assertStatusCode(t, malformed.Publish(context.Background(), yat.Msg{Path: path, Data: []byte("bad-token")}), codes.Unauthenticated)

		unknownIssuer := newAuthClient(t, endpoint, issuer.token(t, authTokenSpec{
			Issuer:   issuer.url + "/other",
			Subject:  "writer-4",
			Audience: []string{"yat-client"},
			Claims: map[string]any{
				"role":  "writer",
				"reply": true,
			},
		}))
		defer closeClient(t, unknownIssuer)
		assertStatusCode(t, unknownIssuer.Publish(context.Background(), yat.Msg{Path: path, Data: []byte("unknown-issuer")}), codes.Unauthenticated)

		writer := newAuthClient(t, endpoint, writerToken(t))
		defer closeClient(t, writer)
		if _, err := writer.Subscribe(context.Background(), yat.Sel{Path: path}, func(context.Context, yat.Msg) {}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("writer.Subscribe() = %v", err)
		}
		if _, err := writer.Handle(context.Background(), yat.Sel{Path: path}, func(context.Context, yat.Path, []byte) []byte { return nil }); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("writer.Handle() = %v", err)
		}

		noReply := newAuthClient(t, endpoint, writerNoReplyToken(t))
		defer closeClient(t, noReply)
		assertStatusCode(t, noReply.Publish(context.Background(), yat.Msg{
			Path:  path,
			Inbox: reply,
			Data:  []byte("reply-denied"),
		}), codes.PermissionDenied)

		emitDenied := mustNewEmitter(t, noReply, context.Background())
		if err := emitDenied.Emit(yat.Msg{
			Path:  path,
			Inbox: reply,
			Data:  []byte("emit-denied"),
		}); err != nil {
			t.Fatal(err)
		}
		assertStatusCode(t, emitDenied.Close(), codes.PermissionDenied)
	})

	t.Run("publish_stream_continues_after_denials", func(t *testing.T) {
		writer := newAuthClient(t, endpoint, writerNoReplyToken(t))
		reader := newAuthClient(t, endpoint, readerToken(t))
		defer closeClient(t, writer)
		defer closeClient(t, reader)

		probe := newSubProbe(t, reader, yat.Sel{Path: path})
		defer probe.Cancel(t)

		stream := mustNewPublisher(t, writer, context.Background())
		assertPublishStreamCode(t, stream.Publish(context.Background(), yat.Msg{
			Path: yat.NewPath("auth/other"),
			Data: []byte("denied-path"),
		}), codes.PermissionDenied)

		assertPublishStreamCode(t, stream.Publish(context.Background(), yat.Msg{
			Path:  path,
			Inbox: reply,
			Data:  []byte("denied-reply"),
		}), codes.PermissionDenied)

		if err := stream.Publish(context.Background(), yat.Msg{
			Path: path,
			Data: []byte("continued"),
		}); err != nil {
			t.Fatal(err)
		}

		assertMsg(t, receiveMsg(t, probe.msgs), path, yat.Path{}, []byte("continued"))
	})
}

func TestGenAuthInterpolatedGrantPaths(t *testing.T) {
	t.Run("cel_expression_and_multiple_paths", func(t *testing.T) {
		exprPath := yat.NewPath("expr/topic")
		staticPath := yat.NewPath("static/topic")

		rules := []yat.Rule{{
			Grants: []yat.Grant{{
				Paths: []string{
					`${{'seg': 'expr'}['seg']}/**`,
					staticPath.String(),
				},
				Actions: []yat.Action{yat.ActionPub, yat.ActionSub},
			}},
		}}

		endpoint := startTLSEndpoint(t, mustRuleSet(t, context.Background(), rules))
		defer endpoint.Close()

		publisher := newTLSClient(t, endpoint)
		subscriber := newTLSClient(t, endpoint)
		defer closeClient(t, publisher)
		defer closeClient(t, subscriber)

		exprProbe := newSubProbe(t, subscriber, yat.Sel{Path: exprPath})
		defer exprProbe.Cancel(t)

		staticProbe := newSubProbe(t, subscriber, yat.Sel{Path: staticPath})
		defer staticProbe.Cancel(t)

		if err := publisher.Publish(context.Background(), yat.Msg{
			Path: exprPath,
			Data: []byte("expr"),
		}); err != nil {
			t.Fatal(err)
		}

		if err := publisher.Publish(context.Background(), yat.Msg{
			Path: staticPath,
			Data: []byte("static"),
		}); err != nil {
			t.Fatal(err)
		}

		assertMsg(t, receiveMsg(t, exprProbe.msgs), exprPath, yat.Path{}, []byte("expr"))
		assertMsg(t, receiveMsg(t, staticProbe.msgs), staticPath, yat.Path{}, []byte("static"))

		assertStatusCode(t, publisher.Publish(context.Background(), yat.Msg{
			Path: yat.NewPath("other/topic"),
			Data: []byte("denied"),
		}), codes.PermissionDenied)
	})

	t.Run("jwt_claim_paths_work_without_expr", func(t *testing.T) {
		issuer := newAuthIssuer(t)
		sharedPath := yat.NewPath("shared/topic")
		ownPath := yat.NewPath("writer-1/topic")
		otherPath := yat.NewPath("writer-2/topic")

		rules := []yat.Rule{{
			JWT: authJWTCond(issuer.url, "yat-client", ""),
			Grants: []yat.Grant{{
				Paths: []string{
					`${claims.sub}/**`,
					sharedPath.String(),
				},
				Actions: []yat.Action{yat.ActionPub, yat.ActionSub},
			}},
		}}

		endpoint := startTLSEndpoint(t, mustRuleSet(t, issuer.context(), rules))
		defer endpoint.Close()

		token := func(tb testing.TB, subject string) *oauth2.Token {
			tb.Helper()
			return issuer.token(tb, authTokenSpec{
				Subject:  subject,
				Audience: []string{"yat-client"},
			})
		}

		writer1Pub := newAuthClient(t, endpoint, token(t, "writer-1"))
		writer1Sub := newAuthClient(t, endpoint, token(t, "writer-1"))
		writer2Sub := newAuthClient(t, endpoint, token(t, "writer-2"))
		defer closeClient(t, writer1Pub)
		defer closeClient(t, writer1Sub)
		defer closeClient(t, writer2Sub)

		ownProbe := newSubProbe(t, writer1Sub, yat.Sel{Path: ownPath})
		defer ownProbe.Cancel(t)

		sharedProbe := newSubProbe(t, writer2Sub, yat.Sel{Path: sharedPath})
		defer sharedProbe.Cancel(t)

		if err := writer1Pub.Publish(context.Background(), yat.Msg{
			Path: ownPath,
			Data: []byte("own"),
		}); err != nil {
			t.Fatal(err)
		}

		if err := writer1Pub.Publish(context.Background(), yat.Msg{
			Path: sharedPath,
			Data: []byte("shared"),
		}); err != nil {
			t.Fatal(err)
		}

		assertMsg(t, receiveMsg(t, ownProbe.msgs), ownPath, yat.Path{}, []byte("own"))
		assertMsg(t, receiveMsg(t, sharedProbe.msgs), sharedPath, yat.Path{}, []byte("shared"))

		assertStatusCode(t, writer1Pub.Publish(context.Background(), yat.Msg{
			Path: otherPath,
			Data: []byte("denied"),
		}), codes.PermissionDenied)
	})

	t.Run("wildcard_interpolation_returns_compile_error", func(t *testing.T) {
		issuer := newAuthIssuer(t)

		rules := []yat.Rule{{
			JWT: authJWTCond(issuer.url, "yat-client", "writer*"),
			Grants: []yat.Grant{{
				Paths:   []string{`${claims.sub}/**`},
				Actions: []yat.Action{yat.ActionPub},
			}},
		}}

		rs := mustRuleSet(t, issuer.context(), rules)
		claims, err := rs.VerifyToken(issuer.context(), issuer.rawToken(t, authTokenSpec{
			Subject:  "writer*",
			Audience: []string{"yat-client"},
		}))
		if err != nil {
			t.Fatal(err)
		}

		_, err = rs.Compile(yat.Principal{Claims: claims})
		assertErrContains(t, err, "wildcard interpolation")
	})

	t.Run("invalid_resolved_claim_path_returns_internal", func(t *testing.T) {
		issuer := newAuthIssuer(t)

		rules := []yat.Rule{{
			JWT: authJWTCond(issuer.url, "yat-client", "writer*"),
			Grants: []yat.Grant{{
				Paths:   []string{`${claims.sub}/**`},
				Actions: []yat.Action{yat.ActionPub},
			}},
		}}

		endpoint := startTLSEndpoint(t, mustRuleSet(t, issuer.context(), rules))
		defer endpoint.Close()

		client := newAuthClient(t, endpoint, issuer.token(t, authTokenSpec{
			Subject:  "writer*",
			Audience: []string{"yat-client"},
		}))
		defer closeClient(t, client)

		assertStatusCode(t, client.Publish(context.Background(), yat.Msg{
			Path: yat.NewPath("writer/topic"),
			Data: []byte("boom"),
		}), codes.Internal)
	})
}

func TestGenAuthMTLS(t *testing.T) {
	ca := newTestCA(t)
	path := yat.NewPath("mtls/topic")
	reply := yat.NewPath("reply/mtls")

	rules := []yat.Rule{
		{
			TLS: authTLSCond("spiffe://example.test/client/writer*"),
			Grants: []yat.Grant{
				{Paths: []string{path.String()}, Actions: []yat.Action{yat.ActionPub}},
				{Paths: []string{"reply/**"}, Actions: []yat.Action{yat.ActionSub}},
			},
		},
		{
			TLS: authTLSCond("spiffe://example.test/client/reader"),
			Grants: []yat.Grant{
				{Paths: []string{path.String()}, Actions: []yat.Action{yat.ActionSub}},
			},
		},
	}

	endpoint := startMTLSEndpoint(t, mustRuleSet(t, context.Background(), rules), ca)
	defer endpoint.Close()

	t.Run("roundtrip_and_wrong_cert", func(t *testing.T) {
		writer := newAuthClient(t, endpoint, nil, ca.clientCert(t, "spiffe://example.test/client/writer"))
		reader := newAuthClient(t, endpoint, nil, ca.clientCert(t, "spiffe://example.test/client/reader"))
		defer closeClient(t, writer)
		defer closeClient(t, reader)

		probe := newSubProbe(t, reader, yat.Sel{Path: path})
		defer probe.Cancel(t)

		if err := writer.Publish(context.Background(), yat.Msg{
			Path:  path,
			Inbox: reply,
			Data:  []byte("mtls-hello"),
		}); err != nil {
			t.Fatal(err)
		}
		assertMsg(t, receiveMsg(t, probe.msgs), path, reply, []byte("mtls-hello"))

		hctx, cancelHandle := context.WithCancel(context.Background())
		hsub, err := reader.Handle(hctx, yat.Sel{Path: path}, func(_ context.Context, gotPath yat.Path, in []byte) []byte {
			if !gotPath.Equal(path) {
				return []byte("wrong-path")
			}
			return append([]byte("mtls-handled:"), in...)
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cancelSub(t, cancelHandle, hsub)

		ctx, cancel := context.WithTimeout(context.Background(), asyncTestTimeout)
		defer cancel()

		var got []yat.Res
		if err := writer.Post(ctx, yat.Req{
			Path:  path,
			Data:  []byte("mtls-post"),
			Limit: 1,
		}, func(res yat.Res) error {
			got = append(got, res)
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		if len(got) != 1 {
			t.Fatalf("len(post responses) = %d", len(got))
		}
		got = assertContainsRes(t, got, yat.Path{}, []byte("mtls-handled:mtls-post"))
		if len(got) != 0 {
			t.Fatalf("unexpected extra responses: %+v", got)
		}

		guest := newAuthClient(t, endpoint, nil, ca.clientCert(t, "spiffe://example.test/client/guest"))
		defer closeClient(t, guest)
		assertStatusCode(t, guest.Publish(context.Background(), yat.Msg{Path: path, Data: []byte("guest")}), codes.PermissionDenied)
		assertStatusCode(t, guest.Post(context.Background(), yat.Req{Path: path}, func(yat.Res) error { return nil }), codes.PermissionDenied)
	})

	t.Run("matching_uri_among_multiple_sans", func(t *testing.T) {
		uriRules := []yat.Rule{
			{
				TLS: authTLSCond("urn:example:client:writer*"),
				Grants: []yat.Grant{
					{Paths: []string{path.String()}, Actions: []yat.Action{yat.ActionPub}},
					{Paths: []string{"reply/**"}, Actions: []yat.Action{yat.ActionSub}},
				},
			},
			{
				TLS: authTLSCond("urn:example:client:reader"),
				Grants: []yat.Grant{
					{Paths: []string{path.String()}, Actions: []yat.Action{yat.ActionSub}},
				},
			},
		}

		endpoint := startMTLSEndpoint(t, mustRuleSet(t, context.Background(), uriRules), ca)
		defer endpoint.Close()

		writer := newAuthClient(t, endpoint, nil, ca.clientCert(t, "urn:example:client:guest", "urn:example:client:writer"))
		reader := newAuthClient(t, endpoint, nil, ca.clientCert(t, "urn:example:client:reader"))
		defer closeClient(t, writer)
		defer closeClient(t, reader)

		probe := newSubProbe(t, reader, yat.Sel{Path: path})
		defer probe.Cancel(t)

		if err := writer.Publish(context.Background(), yat.Msg{
			Path:  path,
			Inbox: reply,
			Data:  []byte("multi-uri"),
		}); err != nil {
			t.Fatal(err)
		}
		assertMsg(t, receiveMsg(t, probe.msgs), path, reply, []byte("multi-uri"))
	})

	t.Run("presented_but_unverified_cert_is_ignored", func(t *testing.T) {
		server := newTestServer(t, mustRuleSet(t, context.Background(), rules))
		states := make(chan tls.ConnectionState, 1)

		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS != nil {
				select {
				case states <- *r.TLS:
				default:
				}
			}
			server.ServeHTTP(w, r)
		}))
		ts.EnableHTTP2 = true
		ts.TLS = &tls.Config{
			Certificates: []tls.Certificate{ca.serverCert(t, testServerName)},
			ClientAuth:   tls.RequestClientCert,
			ClientCAs:    ca.pool,
		}
		ts.StartTLS()
		defer ts.Close()

		endpoint := &tlsEndpoint{
			target:     strings.TrimPrefix(ts.URL, "https://"),
			serverName: testServerName,
			rootCAs:    ca.pool,
			close:      ts.Close,
		}

		client := newAuthClient(t, endpoint, nil, ca.clientCert(t, "spiffe://example.test/client/writer"))
		defer closeClient(t, client)

		assertStatusCode(t, client.Publish(context.Background(), yat.Msg{
			Path: path,
			Data: []byte("unverified-cert"),
		}), codes.PermissionDenied)

		var state tls.ConnectionState
		select {
		case state = <-states:
		case <-time.After(asyncTestTimeout):
			t.Fatal("timed out waiting for tls state")
		}

		if len(state.PeerCertificates) == 0 {
			t.Fatal("server saw no peer certificate")
		}
		if len(state.VerifiedChains) != 0 {
			t.Fatalf("len(VerifiedChains) = %d, want 0", len(state.VerifiedChains))
		}
	})

	t.Run("missing_client_cert_is_rejected", func(t *testing.T) {
		client := newAuthClient(t, endpoint, nil)
		defer closeClient(t, client)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		if err := client.Publish(ctx, yat.Msg{Path: path, Data: []byte("no-cert")}); err == nil {
			t.Fatal("missing client cert unexpectedly succeeded")
		}
	})
}

type subProbe struct {
	cancel context.CancelFunc
	sub    yat.Sub
	msgs   chan yat.Msg
}

func newSubProbe(tb testing.TB, client *yat.Client, sel yat.Sel) *subProbe {
	tb.Helper()

	probe := &subProbe{
		msgs: make(chan yat.Msg, 128),
	}

	ctx, cancel := context.WithCancel(context.Background())
	sub, err := client.Subscribe(ctx, sel, func(_ context.Context, msg yat.Msg) {
		probe.msgs <- msg
	})
	if err != nil {
		cancel()
		tb.Fatal(err)
	}

	probe.cancel = cancel
	probe.sub = sub
	return probe
}

func (p *subProbe) Cancel(tb testing.TB) {
	if tb != nil {
		tb.Helper()
	}
	if p == nil {
		return
	}
	cancelSub(tb, p.cancel, p.sub)
}

func cancelSub(tb testing.TB, cancel context.CancelFunc, sub yat.Sub) {
	if tb != nil {
		tb.Helper()
	}
	if cancel != nil {
		cancel()
	}
	waitSubDone(tb, sub)
}

func waitSubDone(tb testing.TB, sub yat.Sub) {
	if tb != nil {
		tb.Helper()
	}
	if sub == nil {
		return
	}

	select {
	case <-sub.Done():
	case <-time.After(asyncTestTimeout):
		if tb != nil {
			tb.Fatal("timed out waiting for subscription")
		}
	}
}

func newTestServer(tb testing.TB, rules *yat.RuleSet) *yat.Server {
	tb.Helper()

	server, err := yat.NewServer(yat.NewRouter(), yat.ServerConfig{Rules: rules})
	if err != nil {
		tb.Fatal(err)
	}

	return server
}

type tlsEndpoint struct {
	target     string
	serverName string
	rootCAs    *x509.CertPool
	close      func()
}

func (e *tlsEndpoint) Close() {
	if e != nil && e.close != nil {
		e.close()
	}
}

func (e *tlsEndpoint) clientTLSConfig(certificates ...tls.Certificate) *tls.Config {
	return &tls.Config{
		RootCAs:      e.rootCAs,
		ServerName:   e.serverName,
		Certificates: certificates,
	}
}

func startTLSEndpoint(tb testing.TB, rules *yat.RuleSet) *tlsEndpoint {
	tb.Helper()

	ca := newTestCA(tb)
	return startHTTP2TLSEndpoint(tb, rules, ca, false)
}

func startMTLSEndpoint(tb testing.TB, rules *yat.RuleSet, ca *testCA) *tlsEndpoint {
	tb.Helper()

	return startHTTP2TLSEndpoint(tb, rules, ca, true)
}

func startHTTP2TLSEndpoint(tb testing.TB, rules *yat.RuleSet, ca *testCA, requireClientCert bool) *tlsEndpoint {
	tb.Helper()

	server := newTestServer(tb, rules)
	ts := httptest.NewUnstartedServer(server)
	ts.EnableHTTP2 = true
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.serverCert(tb, testServerName)},
	}
	if requireClientCert {
		ts.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		ts.TLS.ClientCAs = ca.pool
	}
	ts.StartTLS()
	return &tlsEndpoint{
		target:     strings.TrimPrefix(ts.URL, "https://"),
		serverName: testServerName,
		rootCAs:    ca.pool,
		close:      ts.Close,
	}
}

func startH2CEndpoint(tb testing.TB, rules *yat.RuleSet) (string, func()) {
	tb.Helper()

	server := newTestServer(tb, rules)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}

	httpServer := &http.Server{
		Handler: h2c.NewHandler(server, &http2.Server{}),
	}

	go func() {
		_ = httpServer.Serve(ln)
	}()

	return ln.Addr().String(), func() {
		_ = httpServer.Close()
		_ = ln.Close()
	}
}

func newTLSClient(tb testing.TB, endpoint *tlsEndpoint) *yat.Client {
	tb.Helper()

	return newClient(tb, endpoint.target, endpoint.clientTLSConfig(), nil)
}

func newInsecureClient(tb testing.TB, target string) *yat.Client {
	tb.Helper()

	client, err := yat.NewClient(target, yat.ClientConfig{})
	if err != nil {
		tb.Fatal(err)
	}

	return client
}

func newAuthClient(tb testing.TB, endpoint *tlsEndpoint, token *oauth2.Token, certificates ...tls.Certificate) *yat.Client {
	tb.Helper()

	return newClient(tb, endpoint.target, endpoint.clientTLSConfig(certificates...), token)
}

func newClient(tb testing.TB, target string, tlsConfig *tls.Config, token *oauth2.Token) *yat.Client {
	tb.Helper()

	cfg := yat.ClientConfig{TLSConfig: tlsConfig}
	if token != nil {
		cfg.TokenSource = staticTokenSource{token: token}
	}

	client, err := yat.NewClient(target, cfg)
	if err != nil {
		tb.Fatal(err)
	}

	return client
}

func closeClient(tb testing.TB, client *yat.Client) {
	tb.Helper()

	if err := client.Close(); err != nil {
		tb.Fatal(err)
	}
}

func mustNewPublisher(tb testing.TB, client *yat.Client, ctx context.Context) *yat.PublishStream {
	tb.Helper()

	stream, err := client.NewPublisher(ctx)
	if err != nil {
		tb.Fatal(err)
	}

	return stream
}

func mustNewEmitter(tb testing.TB, client *yat.Client, ctx context.Context) *yat.EmitStream {
	tb.Helper()

	stream, err := client.NewEmitter(ctx)
	if err != nil {
		tb.Fatal(err)
	}

	return stream
}

func receiveMsg(tb testing.TB, ch <-chan yat.Msg) yat.Msg {
	tb.Helper()

	select {
	case msg := <-ch:
		return msg
	case <-time.After(asyncTestTimeout):
		tb.Fatal("timed out waiting for message")
		return yat.Msg{}
	}
}

func receiveMsgs(tb testing.TB, ch <-chan yat.Msg, n int) []yat.Msg {
	tb.Helper()

	msgs := make([]yat.Msg, 0, n)
	for len(msgs) < n {
		msgs = append(msgs, receiveMsg(tb, ch))
	}

	return msgs
}

type handledReq struct {
	path yat.Path
	data []byte
	err  error
}

func receiveHandledReq(tb testing.TB, ch <-chan handledReq) handledReq {
	tb.Helper()

	select {
	case req := <-ch:
		return req
	case <-time.After(asyncTestTimeout):
		tb.Fatal("timed out waiting for handled request")
		return handledReq{}
	}
}

func assertHandledReq(tb testing.TB, got handledReq, path yat.Path, data []byte) {
	tb.Helper()

	if !got.path.Equal(path) {
		tb.Fatalf("handled path = %q, want %q", got.path.String(), path.String())
	}
	if !bytes.Equal(got.data, data) {
		tb.Fatalf("handled data = %q, want %q", got.data, data)
	}
	if got.err != nil {
		tb.Fatalf("handler context error = %v", got.err)
	}
}

func assertErrContains(tb testing.TB, err error, want string) {
	tb.Helper()

	if err == nil {
		tb.Fatalf("missing error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		tb.Fatalf("error = %q, want substring %q", err.Error(), want)
	}
}

func assertMsg(tb testing.TB, got yat.Msg, path yat.Path, inbox yat.Path, data []byte) {
	tb.Helper()

	if !got.Path.Equal(path) {
		tb.Fatalf("path = %q, want %q", got.Path.String(), path.String())
	}
	if !got.Inbox.Equal(inbox) {
		tb.Fatalf("inbox = %q, want %q", got.Inbox.String(), inbox.String())
	}
	if !bytes.Equal(got.Data, data) {
		tb.Fatalf("data = %q, want %q", got.Data, data)
	}
}

func assertContainsMsg(tb testing.TB, msgs []yat.Msg, path yat.Path, inbox yat.Path, data []byte) []yat.Msg {
	tb.Helper()

	for i, msg := range msgs {
		if msg.Path.Equal(path) && msg.Inbox.Equal(inbox) && bytes.Equal(msg.Data, data) {
			return append(msgs[:i], msgs[i+1:]...)
		}
	}

	tb.Fatalf("missing message path=%q inbox=%q data=%q", path.String(), inbox.String(), data)
	return nil
}

func assertContainsRes(tb testing.TB, res []yat.Res, inbox yat.Path, data []byte) []yat.Res {
	tb.Helper()

	for i, r := range res {
		if r.Inbox.Equal(inbox) && bytes.Equal(r.Data, data) {
			return append(res[:i], res[i+1:]...)
		}
	}

	tb.Fatalf("missing response inbox=%q data=%q", inbox.String(), data)
	return nil
}

func newGRPCRequest(method string, path string, body []byte) *http.Request {
	req := httptest.NewRequest(method, "https://example.test"+path, bytes.NewReader(body))
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Header.Set("content-type", "application/grpc")
	return req
}

func appendGRPCHdr(dst []byte, bodyLen uint32, compressed bool) []byte {
	i := len(dst)
	dst = append(dst, 0, 0, 0, 0, 0)
	if compressed {
		dst[i] = 1
	}
	binary.BigEndian.PutUint32(dst[i+1:], bodyLen)
	return dst
}

func appendGRPCFrame(dst []byte, body []byte) []byte {
	dst = appendGRPCHdr(dst, uint32(len(body)), false)
	return append(dst, body...)
}

func grpcFrameBodies(tb testing.TB, body []byte) [][]byte {
	tb.Helper()

	var bodies [][]byte
	for len(body) > 0 {
		if len(body) < grpcFrameHdrLen {
			tb.Fatalf("short gRPC frame: %d", len(body))
		}

		n := int(binary.BigEndian.Uint32(body[1:grpcFrameHdrLen]))
		if len(body) < grpcFrameHdrLen+n {
			tb.Fatalf("short gRPC frame body: %d < %d", len(body), grpcFrameHdrLen+n)
		}

		bodies = append(bodies, body[grpcFrameHdrLen:grpcFrameHdrLen+n])
		body = body[grpcFrameHdrLen+n:]
	}

	return bodies
}

func assertGRPCStatus(tb testing.TB, rr *httptest.ResponseRecorder, want codes.Code) {
	tb.Helper()
	assertGRPCHeaderStatus(tb, rr.Code, rr.Header(), want)
}

func assertGRPCHeaderStatus(tb testing.TB, code int, header http.Header, want codes.Code) {
	tb.Helper()

	if code != http.StatusOK {
		tb.Fatalf("http status = %d, want %d", code, http.StatusOK)
	}
	if got := header.Get("content-type"); got != "application/grpc" {
		tb.Fatalf("content-type = %q", got)
	}
	if got := header.Get("grpc-status"); got != strconv.Itoa(int(want)) {
		tb.Fatalf("grpc-status = %q, want %d", got, want)
	}
}

func assertHTTPStatus(tb testing.TB, rr *httptest.ResponseRecorder, want int) {
	tb.Helper()

	if rr.Code != want {
		tb.Fatalf("http status = %d, want %d", rr.Code, want)
	}
}

func assertStatusCode(tb testing.TB, err error, want codes.Code) {
	tb.Helper()

	if err == nil {
		tb.Fatal("missing error")
	}
	if got := status.Code(err); got != want {
		tb.Fatalf("status.Code(%v) = %v, want %v", err, got, want)
	}
}

func assertPublishStreamCode(tb testing.TB, err error, want codes.Code) {
	tb.Helper()

	assertErrContains(tb, err, want.String())
}

func marshalProto(tb testing.TB, msg proto.Message) []byte {
	tb.Helper()

	body, err := proto.Marshal(msg)
	if err != nil {
		tb.Fatal(err)
	}

	return body
}

func maxPayloadLen(tb testing.TB, hi int, ok func(int) bool) int {
	tb.Helper()

	lo := 0
	for lo < hi {
		n := (lo + hi + 1) / 2
		if ok(n) {
			lo = n
		} else {
			hi = n - 1
		}
	}

	return lo
}

func nearMaxMpubData(tb testing.TB, path yat.Path, inbox yat.Path) []byte {
	tb.Helper()

	ack := int64(1)
	n := maxPayloadLen(tb, yat.MaxDataLen, func(size int) bool {
		req := &msgv1.MpubRequest{
			Ack:   &ack,
			Path:  []byte(path.String()),
			Inbox: []byte(inbox.String()),
			Data:  make([]byte, size),
		}
		return proto.Size(req) <= maxPubFrameBodyLen
	})

	data := make([]byte, n)
	data[0] = 0x44
	data[len(data)/2] = 0x55
	data[len(data)-1] = 0x66
	return data
}

type testNoFlushWriter struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (w *testNoFlushWriter) Header() http.Header {
	return w.header
}

func (w *testNoFlushWriter) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.body.Write(p)
}

func (w *testNoFlushWriter) WriteHeader(code int) {
	w.code = code
}

type blockingFlushWriter struct {
	header http.Header
	code   int
	body   bytes.Buffer

	firstOnce sync.Once
	first     chan struct{}
	release   chan struct{}
}

func newBlockingFlushWriter() *blockingFlushWriter {
	return &blockingFlushWriter{
		header:  make(http.Header),
		first:   make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (w *blockingFlushWriter) Header() http.Header {
	return w.header
}

func (w *blockingFlushWriter) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.body.Write(p)
}

func (w *blockingFlushWriter) WriteHeader(code int) {
	w.code = code
}

func (w *blockingFlushWriter) Flush() {
	block := false
	w.firstOnce.Do(func() {
		block = true
		close(w.first)
	})
	if block {
		<-w.release
	}
}

type authIssuer struct {
	server *httptest.Server
	signer jose.Signer
	url    string
}

type authTokenSpec struct {
	Issuer    string
	Subject   string
	Audience  []string
	Claims    map[string]any
	TokenType string
}

type staticTokenSource struct {
	token *oauth2.Token
}

func newAuthIssuer(tb testing.TB) *authIssuer {
	tb.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}

	opts := (&jose.SignerOptions{}).WithType("JWT")
	opts.WithHeader("kid", "auth-test")

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       key,
	}, opts)
	if err != nil {
		tb.Fatal(err)
	}

	jwks, err := json.Marshal(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       &key.PublicKey,
			KeyID:     "auth-test",
			Use:       "sig",
			Algorithm: string(jose.RS256),
		}},
	})
	if err != nil {
		tb.Fatal(err)
	}

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	tb.Cleanup(server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                server.URL,
			"authorization_endpoint":                server.URL + "/auth",
			"token_endpoint":                        server.URL + "/token",
			"jwks_uri":                              server.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write(jwks)
	})

	return &authIssuer{
		server: server,
		signer: signer,
		url:    server.URL,
	}
}

func (i *authIssuer) context() context.Context {
	return oidc.ClientContext(context.Background(), i.server.Client())
}

func (i *authIssuer) token(tb testing.TB, spec authTokenSpec) *oauth2.Token {
	tb.Helper()

	tokenType := spec.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}

	return &oauth2.Token{
		AccessToken: i.rawToken(tb, spec),
		TokenType:   tokenType,
	}
}

func (i *authIssuer) rawToken(tb testing.TB, spec authTokenSpec) string {
	tb.Helper()

	issuer := spec.Issuer
	if issuer == "" {
		issuer = i.url
	}

	raw, err := jwt.Signed(i.signer).Claims(jwt.Claims{
		Issuer:   issuer,
		Subject:  spec.Subject,
		Audience: jwt.Audience(spec.Audience),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}).Claims(spec.Claims).Serialize()
	if err != nil {
		tb.Fatal(err)
	}

	return raw
}

func (s staticTokenSource) Token() (*oauth2.Token, error) {
	clone := *s.token
	return &clone, nil
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(tb testing.TB) *testCA {
	tb.Helper()

	cert, key, err := pkigen.NewRoot(pkigen.CN("auth-test-ca"))
	if err != nil {
		tb.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &testCA{
		cert: cert,
		key:  key,
		pool: pool,
	}
}

func (ca *testCA) serverCert(tb testing.TB, dnsName string) tls.Certificate {
	tb.Helper()

	return ca.leafCert(tb, pkigen.CN("yat-test-server"), pkigen.DNS(dnsName))
}

func (ca *testCA) clientCert(tb testing.TB, uris ...string) tls.Certificate {
	tb.Helper()

	opts := []pkigen.CertOpt{pkigen.CN("auth-test-client")}
	for _, raw := range uris {
		opts = append(opts, pkigen.URI(raw))
	}

	return ca.leafCert(tb, opts...)
}

func (ca *testCA) leafCert(tb testing.TB, opts ...pkigen.CertOpt) tls.Certificate {
	tb.Helper()

	cert, key, err := pkigen.NewLeaf(ca.cert, ca.key, opts...)
	if err != nil {
		tb.Fatal(err)
	}

	certPEM := pkigen.EncodeCerts(cert, ca.cert)
	keyPEM, err := pkigen.EncodePrivateKey(key)
	if err != nil {
		tb.Fatal(err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		tb.Fatal(err)
	}

	return tlsCert
}

func mustRuleSet(tb testing.TB, ctx context.Context, rules []yat.Rule) *yat.RuleSet {
	tb.Helper()

	ruleSet, err := yat.NewRuleSet(ctx, rules)
	if err != nil {
		tb.Fatal(err)
	}

	return ruleSet
}

func authJWTCond(issuer string, audience string, subject string) *yat.JWTCond {
	return &yat.JWTCond{
		Issuer:   issuer,
		Audience: audience,
		Subject:  subject,
	}
}

func authTLSCond(uri string) *yat.TLSCond {
	cond := &yat.TLSCond{}
	cond.SAN.URI = uri
	return cond
}
