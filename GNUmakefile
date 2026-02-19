default: build

build:
	go build -o terraform-provider-cortex

install: build
	mkdir -p ~/.terraform.d/plugins/registry.terraform.io/warlock/cortex/0.1.0/linux_amd64
	cp terraform-provider-cortex ~/.terraform.d/plugins/registry.terraform.io/warlock/cortex/0.1.0/linux_amd64/

test:
	go test ./... -v -count=1

testacc:
	TF_ACC=1 go test ./... -v -count=1 -timeout 120m

lint:
	golangci-lint run ./...

clean:
	rm -f terraform-provider-cortex

.PHONY: build install test testacc lint clean
