FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /proxy .

FROM scratch
COPY --from=builder /proxy /proxy
ARG PORT=7890
EXPOSE ${PORT}
ENTRYPOINT ["/proxy"]
