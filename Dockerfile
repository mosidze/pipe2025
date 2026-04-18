FROM golang:alpine as builder

WORKDIR /src
COPY . /src
RUN go install github.com/coolbet/login/cmd/login

FROM alpine:latest
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=builder /src/login /app/
EXPOSE 8080
CMD ["/app/login"]