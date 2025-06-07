.PHONY: build docker fmt lint test cover clean install-deps serve

# Variables
DOCKER_IMAGE := rbac-atlas
DOCKER_TAG := latest
HUGO_PORT := 1313

install-deps:
	@echo "Installing dependencies..."
	npm install -g playwright
	npm install --save-dev prettier prettier-plugin-go-template
	python3 -m pip install 'pagefind[extended]'

prebuild:
	@echo "Building site..."
	hugo --minify
	@echo "Building Pagefind index..."
	python3 -m pagefind --site public

build: prebuild fmt lint

docker: build
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

fmt:
	@echo "Formatting Markdown files..."
	npm run fmt

lint:
	@echo "Checking Markdown formatting..."
	npm run lint

test:
	@echo "Running tests..."
	npm run test

cover:
	@echo "Running tests with coverage..."
	npx playwright test --reporter=html

clean:
	@echo "Cleaning up..."
	rm -rf public
	rm -rf resources
	rm -rf node_modules
	rm -rf playwright-report

serve: build
	@echo "Starting Hugo server..."
	hugo server -D --bind 0.0.0.0 -p $(HUGO_PORT)

get-manifests:
	@echo "Fetching manifests..."
	for f in charts/*/; do \
		[ -d "$$f" ] && \
		filename="$${f#charts/}" && \
		filename="$${filename%\/}" && \
		echo "Processing $$filename" && \
		rbac-ops ingest "$$f" -o json > "manifests/$$filename.json"; \
	done

generate-pages:
	@echo "Generating pages..."
	for f in manifests/*.json; do \
		python json2hugo.py "$$f" -o content/charts/; \
	done
