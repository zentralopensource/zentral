from django.test import TestCase
from django.urls import reverse
from drf_spectacular.drainage import GENERATOR_STATS
from drf_spectacular.generators import SchemaGenerator
from drf_spectacular.settings import spectacular_settings


class OpenAPISchemaTestCase(TestCase):
    maxDiff = None

    def _generate_schema(self):
        # GENERATOR_STATS.silence() mutes drf-spectacular's warning/summary output,
        # which it prints straight to stderr (not via logging) during generation.
        with GENERATOR_STATS.silence():
            return SchemaGenerator().get_schema(request=None, public=True)

    # the decentralized enum name overrides

    def test_enum_name_overrides_registered_per_app(self):
        # Each app's openapi submodule registers its overrides at startup via
        # zentral.utils.drf_spectacular.register_enum_name_overrides.
        for name in (
            "CertIssuerBackendEnum",
            "InventoryPlatformEnum",
            "OsqueryPlatformEnum",
            "MdmPlatformEnum",
            "InventoryItemCollectionOptionEnum",
            "KeyUsageEnum",
        ):
            self.assertIn(name, spectacular_settings.ENUM_NAME_OVERRIDES)

    # schema generation

    def test_schema_generates(self):
        schema = self._generate_schema()
        self.assertTrue(schema["openapi"].startswith("3"))
        self.assertTrue(schema["paths"])

    def test_schema_limited_to_management_api(self):
        # the keep_management_api_only preprocessing hook drops every non /api/ path
        schema = self._generate_schema()
        for path in schema["paths"]:
            self.assertTrue(path.startswith("/api/"), path)

    # documentation endpoints

    def test_schema_endpoint(self):
        with GENERATOR_STATS.silence():
            response = self.client.get(reverse("schema"))
        self.assertEqual(response.status_code, 200)

    def test_swagger_ui_endpoint(self):
        response = self.client.get(reverse("swagger-ui"))
        self.assertEqual(response.status_code, 200)
