# Build stage
FROM klakegg/hugo:latest AS builder

WORKDIR /src
COPY . .
RUN hugo --minify

# Production stage
FROM nginx:alpine

COPY --from=builder /src/public /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
