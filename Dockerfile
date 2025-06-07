# Build stage
FROM klakegg/hugo:latest AS builder

# Install Python, pip, Node.js and npm
RUN apk add --no-cache python3 py3-pip nodejs npm

# Install pagefind and prettier dependencies
RUN python3 -m pip install 'pagefind[extended]'
RUN npm install -g prettier
RUN npm install --save-dev prettier-plugin-go-template

WORKDIR /src
COPY . .
RUN hugo --minify
RUN python3 -m pagefind --site public

# Production stage
FROM nginx:alpine

COPY --from=builder /src/public /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
