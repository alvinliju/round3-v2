FROM golang:1.24-bookworm AS base

WORKDIR /app

COPY go.* ./

RUN go mod download

COPY . .

RUN go build -o main main.go

EXPOSE 8000

CMD ["./main"]
