# RBAC Atlas

A curated database of identities and RBAC policies in Kubernetes projects, with security annotations that highlight granted permissions, potential risks, and possible abuse scenarios.

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/rbac-atlas.git
   cd rbac-atlas
   ```

2. Install dependencies:
   ```bash
   make install-deps
   ```

3. Start the development server:
   ```bash
   make serve
   ```

4. Visit http://localhost:1313

## Building and Deployment

### Local Development
```bash
make serve  # Start development server
make build  # Build static site
make test   # Run tests
```

### Docker Deployment
```bash
make docker  # Build container
docker-compose up  # Run with Nginx
```

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

For security concerns, please see our [Security Policy](SECURITY.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.




