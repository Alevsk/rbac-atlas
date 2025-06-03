.PHONY: build docker fmt lint test cover clean install-deps serve

# Variables
DOCKER_IMAGE := rbac-atlas
DOCKER_TAG := latest
HUGO_PORT := 1313

install-deps:
	npm install -g playwright

build:
	hugo --minify

docker:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

fmt:
	prettier --write "content/**/*.md" "layouts/**/*.html"

lint:
	prettier --check "content/**/*.md" "layouts/**/*.html"

test:
	npx playwright test

cover:
	npx playwright test --reporter=html

clean:
	rm -rf public
	rm -rf resources
	rm -rf node_modules
	rm -rf playwright-report

serve:
	hugo server -D --bind 0.0.0.0 -p $(HUGO_PORT)

get-manifests:
	for f in charts/*/; do \
		[ -d "$$f" ] && \
		filename="$${f#charts/}" && \
		filename="$${filename%\/}" && \
		rbac-ops ingest "$$f" -o json > "manifests/$$filename.json"; \
	done

generate-pages:
	for f in manifests/*.json; do \
		python json2hugo.py "$$f" -o content/charts/; \
	done
