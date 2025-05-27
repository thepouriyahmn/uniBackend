FROM golang:1.21

WORKDIR /app

COPY . .

RUN go mod tidy
RUN go build -o main

EXPOSE 9001

CMD ["./main"]