.PHONY: generate build tidy clean

generate:
	templ generate

build: generate
	CGO_ENABLED=0 go build -o wicket ./cmd/wicket

tidy:
	go mod tidy

clean:
	rm -f wicket
	find . -name '*_templ.go' -delete

# Development: run with auto-reload (requires air)
dev:
	templ generate --watch &
	go run ./cmd/wicket serve --config config.example.yaml

docker:
	docker compose build

run:
	docker compose up
