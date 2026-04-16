FROM golang:1.22-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/login ./cmd/login

FROM alpine:3.20

# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates curl

COPY --from=builder /out/login /login

USER 65532:65532
EXPOSE 8080

ENTRYPOINT ["/login"]
