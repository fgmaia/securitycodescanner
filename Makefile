run:
	go run main.go

test:
	go test -cover -race ./...

compose-up:
	docker-compose up -d

docker-exec:
	docker exec -it securitycodescanner /bin/bash

mockary:
	~/go/bin/mockery --all