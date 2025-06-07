# Build stage
FROM hugomods/hugo:latest AS builder

# Install system dependencies
RUN apk add --no-cache nodejs npm python3 py3-pip

# Set working directory
WORKDIR /src

# Copy package files first to leverage Docker cache
COPY package*.json ./

# Install Node.js dependencies
RUN npm install
RUN npm install -g prettier
RUN npm install --save-dev prettier-plugin-go-template

# Setup Python virtual environment and install dependencies
RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"
RUN pip install --no-cache-dir 'pagefind[extended]' djlint

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
FROM nginx:alpine

# Copy the built site
COPY --from=builder /src/public /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
