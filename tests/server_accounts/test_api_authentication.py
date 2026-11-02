from datetime import timedelta, date
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import APIToken, User
from tests.zentral_test_utils.zentral_api_test_case import ZentralAPITestCase


class ApiAuthenticationTestCase(ZentralAPITestCase):
    def test_api_authentication(self):
        self.set_permissions("monolith.view_manifest")
        response = self.get(reverse("monolith_api:manifests"))
        self.assertEqual(response.status_code, 200)

    def test_api_authentication_invalide(self):
        self.set_permissions("monolith.view_manifest")
        self.api_key = "xxx-invalid-key-xxx"
        response = self.get(reverse("monolith_api:manifests"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {'detail': 'Invalid token.'})
        self.api_key = "ztlx_invalid_key_xxx"
        response = self.get(reverse("monolith_api:manifests"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {'detail': 'Invalid ztl token.'})

    def test_api_authentication_expiry(self):
        self.set_permissions("monolith.view_manifest")
        expiry_date = date.today() + timedelta(days=1)
        _, new_api_key = APIToken.objects.create_for_user(self.service_account, expiry=expiry_date)
        self.api_key = new_api_key
        response = self.get(reverse("monolith_api:manifests"))
        self.assertEqual(response.status_code, 200)

        expired_date = date.today() - timedelta(days=1)
        _, expired_api_key = APIToken.objects.create_for_user(self.service_account, expiry=expired_date)
        self.api_key = expired_api_key
        response = self.get(reverse("monolith_api:manifests"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {'detail': 'Invalid token.'})

    def test_api_user_inactive(self):
        self.set_permissions("monolith.view_manifest")
        self.service_account.is_active = False
        self.service_account.save()
        response = self.get(reverse("monolith_api:manifests"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {'detail': 'User inactive or deleted.'})

    def test_api_superuser_token_refused(self):
        self.set_permissions("monolith.view_manifest")
        user = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.io")
        token, self.api_key = APIToken.objects.create_for_user(user)
        # a token of before the upgrade, that create_for_user cannot write anymore
        User.objects.filter(pk=user.pk).update(is_superuser=True)
        with self.assertLogs("zentral.accounts.api_authentication", level="ERROR") as cm:
            response = self.get(reverse("monolith_api:manifests"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {'detail': 'A superuser has no API token.'})
        self.assertEqual(cm.output, [f"ERROR:zentral.accounts.api_authentication:"
                                     f"API token {token.pk} of superuser {user.pk} refused"])
