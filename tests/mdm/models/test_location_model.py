
from django.test import TestCase

from tests.mdm.utils import force_location


class MDMLocationModelTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.location = force_location()

    def test_location_serialize_for_event(self):
        keys_only = self.location.serialize_for_event(keys_only=True)

        self.assertEqual(
            keys_only,
            {"pk": self.location.pk, "mdm_info_id": str(self.location.mdm_info_id)},
        )

        all_keys = self.location.serialize_for_event(keys_only=False)

        self.assertEqual(
            all_keys,
            {
                "pk": self.location.pk,
                "mdm_info_id": str(self.location.mdm_info_id),
                "server_token_expiration_date": self.location.server_token_expiration_date,
                "organization_name": self.location.organization_name,
                "country_code": self.location.country_code,
                "library_uid": self.location.library_uid,
                "name": self.location.name,
                "platform": self.location.platform,
                "website_url": self.location.website_url,
            },
        )
