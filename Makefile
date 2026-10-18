.PHONY: test gates all
all: test gates
test:
	go test ./... -race
gates:
	./scripts/features-are-bound.sh
	./scripts/readme-numbers.sh
	./scripts/base-images-pinned-by-digest.sh
	./scripts/dependencies-are-argued.sh
	./scripts/no-owner-quotes.sh
	./scripts/no-long-dashes.sh
	./scripts/private-keys-stay-in-the-store.sh
