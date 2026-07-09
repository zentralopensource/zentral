"""
drf-spectacular configuration for the OpenAPI schema.

"""

def keep_management_api_only(endpoints, **kwargs):
    """Restrict the schema to the management API.

    The management API is served entirely under /api/. The agent-facing public
    endpoints (mounted under /public/, and at a legacy top-level path for some
    apps) are dropped.
    """
    return [endpoint for endpoint in endpoints if endpoint[0].startswith("/api/")]


SPECTACULAR_SETTINGS = {
    "TITLE": "Zentral API",
    "DESCRIPTION": "Management API for the Zentral MDM platform.",
    "EXTERNAL_DOCS": {'url': 'https://docs.zentral.io', 'description': 'Zentral offical documentation'},
    "VERSION": "1.0.0",
    "COMPONENT_SPLIT_REQUEST": True,
    "GENERIC_ADDITIONAL_PROPERTIES": 'dict',
    "SERVE_INCLUDE_SCHEMA": False,
    "SCHEMA_PATH_PREFIX": r"/(api)/",
    "PREPROCESSING_HOOKS": ["server.openapi.keep_management_api_only"],
    # Colliding choice-field enum names are registered per-app at startup.
    "ENUM_NAME_OVERRIDES": {},
}
