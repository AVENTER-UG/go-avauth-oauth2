FROM golang:alpine as builder

WORKDIR /build

ADD . /build/

RUN apk add git && \
    go get -d



RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags "-X main.MinVersion=`date -u +%Y%m%d%.H%M%S` -extldflags \"-static\"" -o main

FROM alpine
MAINTAINER Andreas Peters <support@aventer.biz>

ENV AUTH_SERVER "http://avauth"
ENV CALLBACKURL "http://localhost:9094"
ENV CLIENTID "1"
ENV CLIENTSECRET "2"

RUN adduser -S -D -H -h /app appuser

USER appuser

COPY --from=builder /build/main /app/

COPY static /app/static

EXPOSE 9094

WORKDIR "/app"

CMD ["./main"]
