FROM golang:1.9-alpine
FROM golang:1.9-alpine as builder


ARG APPNAME=rabbitmq-api

RUN apk update; \
    apk add openssl ca-certificates git

RUN echo ${GOPATH}; go get -u github.com/golang/dep/cmd/dep

WORKDIR ${GOPATH}/src/${APPNAME}

COPY . .

RUN dep ensure

RUN go build -o ${APPNAME}

FROM alpine:3.7

ARG APPNAME=rabbitmq-api
ENV APPNAME ${APPNAME}

RUN apk update; \
    apk add openssl ca-certificates git

WORKDIR /app

COPY --from=builder /go/src/${APPNAME}/${APPNAME} .

EXPOSE 3300

CMD "/app/${APPNAME}"

