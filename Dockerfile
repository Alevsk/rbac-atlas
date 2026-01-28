# Build stage
FROM hugomods/hugo:latest AS builder

# Install system dependencies
RUN apk add --no-cache nodejs npm python3

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set working directory
WORKDIR /src

# Copy package files first to leverage Docker cache
COPY package*.json ./

# Install Node.js dependencies
RUN npm install
RUN npm install -g prettier
RUN npm install --save-dev prettier-plugin-go-template

# Setup Python virtual environment and install dependencies
COPY requirements.txt ./
RUN uv venv /venv && VIRTUAL_ENV=/venv uv pip install --no-cache -r requirements.txt
ENV PATH="/venv/bin:$PATH"

# Copy the rest of the application
COPY . .

# Format and lint files
RUN npm run fmt && npm run lint
RUN djlint --reformat layouts/**/*.html && djlint --check layouts/**/*.html

# Build the site
ENV HUGO_ENV=production
ENV HUGO_RESOURCEDIR=/src/resources
RUN hugo --gc --minify
RUN python3 -m pagefind --site public

# Production stage
FROM docker.io/library/nginx:alpine

# Copy the built site and set permissions
COPY --from=builder /src/public /usr/share/nginx/html

# Copy nginx configuration
COPY --from=builder  /src/nginx.conf /etc/nginx/nginx.conf

# Switch to non-root user
USER nginx

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
