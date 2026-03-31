FROM --platform=$BUILDPLATFORM golang:1.26 AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN GOARM=7 GOOS=$TARGETOS GOARCH=$TARGETARCH bin/build -trimpath

# for debugging &c
FROM alpine:3 AS alpine

# yat sub outputs in JSON
RUN apk add --no-cache jq

COPY --from=build /src/yat /usr/local/bin/yat

# just yat
FROM scratch

COPY --from=build /src/yat /yat
ENTRYPOINT ["/yat"]
