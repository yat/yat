FROM golang:1.26 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN bin/build

FROM scratch

COPY --from=build /src/yat /yat
ENTRYPOINT ["/yat"]
