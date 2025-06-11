.PHONY: build docker fmt lint test cover clean install-deps serve

# Variables
DOCKER_IMAGE := alevsk/rbac-atlas
DOCKER_TAG := latest
HUGO_PORT := 1313

install-deps:
	@echo "Installing dependencies..."
	npm install -g playwright
	npm install --save-dev prettier prettier-plugin-go-template
	python3 -m pip install 'pagefind[extended]' djlint

prebuild:
	@echo "Building site..."
	hugo --minify
	@echo "Building Pagefind index..."
	python3 -m pagefind --site public

build: prebuild fmt lint

docker:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

fmt:
	@echo "Formatting Markdown files..."
	npm run fmt
	@echo "Formatting HTML files..."
	djlint --reformat layouts/**/*.html

lint:
	@echo "Checking Markdown formatting..."
	npm run lint
	@echo "Checking HTML formatting..."
	djlint --check layouts/**/*.html

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

serve:
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


json2markdown:
	@echo "Generating pages..."
	python json2hugo.py -f manifests/ -o content/

generate-pages: json2markdown fmt lint
