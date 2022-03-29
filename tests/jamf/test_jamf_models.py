from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.jamf.models import JamfInstance
from zentral.core.secret_engines import secret_engines


class JamfModelsTestCase(TestCase):
    def _force_jamf_instance(self):
        jamf_instance = JamfInstance.objects.create(
            host="{}.example.com".format(get_random_string(12)),
            port=443,
            path="/JSSResource",
            user=get_random_string(12)
        )
        jamf_instance.set_password(get_random_string(12))
        super(JamfInstance, jamf_instance).save()
        return jamf_instance

    # jamf instance

    def test_jamf_instance_password_serialization(self):
        jamf_instance = self._force_jamf_instance()
        self.assertEqual(jamf_instance.serialize()["password"], jamf_instance.password)
        self.assertEqual(jamf_instance.serialize(decrypt_password=True)["password"], jamf_instance.get_password())

    def test_jamf_instance_rewrap_secrets(self):
        # default secret engine
        jamf_instance = self._force_jamf_instance()
        self.assertEqual(jamf_instance.password.split("$")[0], "noop")
        password = jamf_instance.get_password()
        jamf_instance.rewrap_secrets()
        self.assertEqual(jamf_instance.get_password(), password)
        # upgrade to fernet secret engine
        secret_engines.load_config({
            "fernet": {"backend": "zentral.core.secret_engines.backends.fernet",
                       "passwords": ["undeuxtrois"]}
        })
        jamf_instance.rewrap_secrets()
        self.assertEqual(jamf_instance.get_password(), password)
        self.assertEqual(jamf_instance.password.split("$")[0], "fernet")
