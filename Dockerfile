# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY pkg/ pkg/
COPY internal/ internal/
COPY cmd/ cmd/
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server

FROM alpine:3.20
WORKDIR /app
COPY --from=build /out/server /app/server
EXPOSE 8443
# Writes ca.pem into /app on start; fetch it with `docker cp` for clients.
ENTRYPOINT ["/app/server", "--addr", "0.0.0.0:8443", "--ca-out", "/app/ca.pem"]
