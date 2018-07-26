#
# Build and Test RabbitMQ broker for Akkeris PAAS
#

APPNAME=rabbitmq-api
VERSION=1.0
TAG=$(VERSION)-dev

SRC=*.go

DOCKERFILE=Dockerfile

.PHONY: init docker

build: $(APPNAME)
	go build -o $(APPNAME)

$(APPNAME):  Gopkg.lock $(SRC)

Gopkg.lock: Gopkg.toml $(SRC)
	dep ensure

docker: $(DOCKERFILE) $(SRC)
	docker build -t $(APPNAME) $(BUILD_ARGS) $(EXTRA_ARGS) -f $(DOCKERFILE) .
	docker tag $(APPNAME) $(APPNAME):$(TAG)

all: $(APPNAME) docker

init:
	dep init

clean: clean_docker clean_app

clean_docker:
	docker rmi -f $(APPNAME):$(TAG) $(APPNAME)

clean_app:
	-rm -f $(APPNAME)
