from django.urls import reverse
from tests.zentral_test_utils.zentral_api_test_case import ZentralAPITestCase


class ApiAuthenticationTestCase(ZentralAPITestCase):

    def test_api_authentication(self):
        self.set_permissions("monolith.view_manifest")

        self.api_key = "xxx-invalid-key-xxx"
        response = self.get(reverse("monolith_api:manifests"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {'detail': 'Invalid token.'})
        self.api_key = "ztlx_invalid_key_xxx"
        response = self.get(reverse("monolith_api:manifests"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {'detail': 'Invalid ztl token.'})

    def test_api_user_inactive(self):
        self.set_permissions("monolith.view_manifest")
        self.service_account.is_active = False
        self.service_account.save()

        response = self.get(reverse("monolith_api:manifests"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {'detail': 'User inactive or deleted.'})
