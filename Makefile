DOCKER_NAME="misp2sentinel"
DOCKER_IMAGE=$(DOCKER_NAME)
DOCKER_PATH="."
DEV_FILE="dev.env"

all: build run

build:
	docker build -t $(DOCKER_IMAGE) $(DOCKER_PATH)

run:
	docker run --name=$(DOCKER_NAME) -ti --rm --env-file=$(DEV_FILE) --read-only -v $$(pwd)/data:/data $(DOCKER_IMAGE)

clean:
	docker rm -f $(DOCKER_NAME) || true
	docker rmi -f $(DOCKER_IMAGE) || true
	docker system prune -af
