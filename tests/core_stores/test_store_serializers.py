from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.core.stores.serializers import StoreSerializer, StoreProvisioningSerializer
from .utils import force_store


class StoreSerializersTestCase(TestCase):
    maxDiff = None

    def test_store_serializer_missing_fields(self):
        s = StoreSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"name": ["This field is required."],
             "backend": ["This field is required."]},
        )

    def test_creation_slug_collision(self):
        force_store(name="YoLo")
        s = StoreSerializer(data={
            "name": "YOLO",
            "backend": "HTTP",
            "http_kwargs": {
                "endpoint_url": "https://www.example.com/api/"
            }
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"name": ["A store with the same slugified version of this name already exists"]},
        )

    def test_update_slug_collision(self):
        store1 = force_store(name=get_random_string(12).lower())
        store2 = force_store()
        s = StoreSerializer(
            instance=store2.instance,
            data={
                "name": store1.name.upper(),
                "backend": "HTTP",
                "http_kwargs": {
                    "endpoint_url": "https://www.example.com/api/"
                }
            }
        )
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"name": ["A store with the same slugified version of this name already exists"]},
        )

    def test_store_provisioning_serializer_missing_fields(self):
        s = StoreProvisioningSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"name": ["This field is required."],
             "backend": ["This field is required."]},
        )

    def test_store_provisioning_serializer_creation(self):
        name = get_random_string(12).upper()
        s = StoreProvisioningSerializer(data={
            "name": name,
            "backend": "HTTP",
            "http_kwargs": {
                "endpoint_url": "https://www.example.com/api/"
            }
        })
        self.assertTrue(s.is_valid())
        db_store = s.save(provisioning_uid=get_random_string(12))
        self.assertEqual(db_store.slug, name.lower())
