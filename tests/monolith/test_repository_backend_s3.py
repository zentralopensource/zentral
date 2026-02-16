import io
import plistlib
from collections.abc import Callable
from types import SimpleNamespace
from typing import Dict, Iterable
from unittest.mock import Mock

from django.test import SimpleTestCase, TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.monolith.exceptions import RepositoryError
from zentral.contrib.monolith.models import Repository, RepositoryBackend
from zentral.contrib.monolith.repository_backends.s3 import S3Repository


class S3RepositoryModelTests(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.repository = Repository.objects.create(
            name=get_random_string(12),
            backend=RepositoryBackend.S3,
            backend_kwargs={},
        )
        cls.backend_kwargs = {
            "bucket": "bucket",
            "region_name": "eu-central-1",
            "prefix": "prefix",
            "access_key_id": "0123456",
            "secret_access_key": "6543210"
        }
        cls.repository.set_backend_kwargs(cls.backend_kwargs)
        cls.repository.save()
        cls.repository.refresh_from_db()

    def test_get_kwargs(self):
        self.assertEqual(self.repository.get_backend_kwargs(), self.backend_kwargs)

    def test_get_backend_kwargs_for_event(self):
        backend_kwargs_for_event = self.backend_kwargs.copy()
        backend_kwargs_for_event.pop("secret_access_key")
        backend_kwargs_for_event["secret_access_key_hash"] = (
            "d80a33333f2b696325762a3478b0497b8dc08edb8e3d56848aa0f8f2cd439826"
        )
        self.assertEqual(self.repository.get_backend_kwargs_for_event(), backend_kwargs_for_event)

    def test_rewrap_secrets(self):
        self.repository.rewrap_secrets()
        self.repository.save()
        self.repository.refresh_from_db()
        self.assertEqual(self.repository.get_backend_kwargs(), self.backend_kwargs)


class NoSuchKey(Exception):
    pass


class S3RepositoryGetAllCatalogContentTests(SimpleTestCase):

    def _create_repo(self, client, prefix="repo"):
        namespace = SimpleNamespace(
            name="testrepo",
            backend_kwargs={
                "bucket": "my-bucket",
                "region_name": "eu-central-1",
                "prefix": prefix,
            },
        )
        repo = S3Repository(namespace)
        repo.__dict__["_client"] = client
        return repo

    def _mock_paginator(self, keys: Iterable[str]) -> Mock:
        paginator = Mock()
        paginator.paginate.return_value = [{"Contents": [{"Key": key} for key in keys]}]
        return paginator

    def _mock_client(
            self,
            get_object_side_effect: Callable[[str, str], Dict[str, bytes]],
            paginator=None
            ) -> Mock:
        client = Mock()
        client.get_object.side_effect = get_object_side_effect
        client.get_paginator.return_value = paginator

        client.exceptions = SimpleNamespace(NoSuchKey=NoSuchKey)

        return client

    def test_catalogs_all_present_returns_directly(self):
        # given
        catalog_list = [{"name": "A", "version": "1.0", "catalogs": ["production"]}]
        catalog_bytes = plistlib.dumps(catalog_list, fmt=plistlib.FMT_XML)

        def get_object_side_effect(Bucket, Key):
            self.assertEqual(Bucket, "my-bucket")
            self.assertEqual(Key, "repo/catalogs/all")
            return {"Body": io.BytesIO(catalog_bytes)}

        client = self._mock_client(get_object_side_effect)
        repo = self._create_repo(client)

        # when
        actual = repo.get_all_catalog_content()

        # then
        self.assertEqual(actual, catalog_bytes)
        client.get_paginator.assert_not_called()

    def test_fallback_aggregates_pkgsinfo_plists(self):
        # given
        pkg_a = {"name": "A", "version": "1.0", "catalogs": ["production"], "notes": "ignore me", "_key": "ignore me"}
        pkg_b = {"name": "B", "version": "2.0", "catalogs": ["testing"]}

        objects = {
            "repo/pkgsinfo/A.plist": plistlib.dumps(pkg_a, fmt=plistlib.FMT_XML),
            "repo/pkgsinfo/sub/B.plist": plistlib.dumps(pkg_b, fmt=plistlib.FMT_XML),
            "repo/pkgsinfo/readme.txt": b"not a plist",
        }

        def get_object_side_effect(Bucket, Key):
            if Key == "repo/catalogs/all":
                raise NoSuchKey()
            if Key in objects:
                return {"Body": io.BytesIO(objects[Key])}
            raise AssertionError(f"Unexpected Key requested: {Key}")

        paginator = self._mock_paginator([
            "pkgsinfo/",
            "pkgsinfo/A.plist",
            "pkgsinfo/readme.txt",
            "pkgsinfo/sub/",
            "pkgsinfo/sub/B.plist",
        ])

        client = self._mock_client(get_object_side_effect, paginator)
        repo = self._create_repo(client)

        # when
        out = repo.get_all_catalog_content()
        data = plistlib.loads(out)

        # then
        self.assertEqual(sorted(d["name"] for d in data), ["A", "B"])
        client.get_paginator.assert_called_once_with("list_objects_v2")
        paginator.paginate.assert_called_once_with(Bucket="my-bucket", Prefix="repo/pkgsinfo/")
        self.assertTrue(all("notes" not in d for d in data))
        self.assertTrue(all("_key" not in d for d in data))

    def test_fallback_raises_when_no_pkgsinfo_found(self):
        # given
        def get_object_side_effect(Bucket, Key):
            if Key == "repo/catalogs/all":
                raise NoSuchKey()
            raise AssertionError("Should not request any other keys")

        paginator = self._mock_paginator([])

        mock_client = self._mock_client(get_object_side_effect, paginator)
        repo = self._create_repo(mock_client)

        # when / then
        with self.assertRaises(RepositoryError):
            repo.get_all_catalog_content()

    def test_fallback_raises_on_invalid_plist(self):
        # given
        def get_object_side_effect(Bucket, Key):
            if Key == "repo/catalogs/all":
                raise NoSuchKey()
            if Key == "repo/pkgsinfo/broken.plist":
                return {"Body": io.BytesIO(b"definitely-not-a-plist")}
            raise AssertionError(f"Unexpected Key requested: {Key}")

        paginator = self._mock_paginator(["pkgsinfo/broken.plist"])

        mock_client = self._mock_client(get_object_side_effect, paginator)
        repo = self._create_repo(mock_client)

        # when / then
        with self.assertRaises(RepositoryError):
            repo.get_all_catalog_content()

    def test_fallback_raises_on_failing_paginator(self):
        # given
        def get_object_side_effect(Bucket, Key):
            if Key == "repo/catalogs/all":
                raise NoSuchKey()
            raise AssertionError("Should not request any other keys")

        paginator = Mock()
        paginator.paginate.side_effect = Exception("There`s something strange in your neighborhood.")

        mock_client = self._mock_client(get_object_side_effect, paginator)
        repo = self._create_repo(mock_client)

        # when / then
        with self.assertRaises(RepositoryError):
            repo.get_all_catalog_content()
