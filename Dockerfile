FROM golang:alpine AS build-env
WORKDIR $GOPATH/src/webhook
COPY . .
RUN   apk -u add curl git && \
      curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh && \
      dep ensure && \
      go build -o /webhook


FROM alpine
WORKDIR /app
COPY --from=build-env /webhook .
ENTRYPOINT ./webhook


