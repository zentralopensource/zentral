# OpenAPI Documentation for Zentral

This project adds OpenAPI/Swagger documentation to the Zentral API using `drf-spectacular`. The setup automatically generates comprehensive API documentation from Django REST Framework views and serializers.

## Project Description

Zentral is a unified endpoint management and security platform. This OpenAPI integration provides:

- **Complete API documentation** for all Zentral endpoints
- **Interactive Swagger UI** for exploring and testing APIs
- **Automatic schema generation** from Django REST Framework code
- **Comprehensive coverage** of all apps: core, contrib, and server modules

## 1. Installation

```bash
pip install -r requirements.txt
```

## 2. Regenerating Specs

To update the OpenAPI schema after making API changes:

```bash
docker compose exec web python server/manage.py spectacular --file openapi-schema.yaml
```

## 3. Viewing Specs Locally

Start a local HTTP server to view the documentation:

```bash
python -m http.server 8080 && open http://localhost:8080/swagger-ui.html
```

We didn't manage to get this working in the current docker-compose environment, but that should be
a relatively straightforward next step, should we like this solution.

## Files

- `openapi-schema.yaml` - Generated OpenAPI 3.0 specification
- `swagger-ui.html` - Standalone Swagger UI for local viewing
- `server/server/settings.py` - Django settings with drf-spectacular configuration
- `server/server/urls.py` - URL patterns for schema endpoints

## Available Endpoints

The generated schema includes documentation for:

- **Stores API** (`/api/stores/`) - Store management
- **Inventory APIs** - Device and application inventory
- **Compliance Checks** - Security compliance monitoring
- **Incidents** - Security incident management
- **Probes** - Event collection and monitoring
- **Realms** - Authentication and user management
- **Contrib Apps** - Jamf, Munki, Osquery, Santa integrations
