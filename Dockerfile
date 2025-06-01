FROM golang:1.24.1

WORKDIR /app

COPY go.mod go.sum ./


COPY . .

RUN go build -o backend .

EXPOSE 9001

CMD ["./backend"]