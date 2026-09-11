from datetime import datetime, timedelta
from unittest.mock import patch
import uuid

from django.contrib.auth.models import Group
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase

from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from zentral.utils.time import naive_utcnow
from .utils import force_task_result


class BaseAPIViewsTestCase(TestCase, LoginCase, RequestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.other_user = User.objects.create_user(
            get_random_string(12), "{}@zentral.io".format(get_random_string(12)), get_random_string(12)
        )
        cls.superuser = User.objects.create_user(
            get_random_string(12), "{}@zentral.io".format(get_random_string(12)), get_random_string(12),
            is_superuser=True
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "base_api"

    # RequestCase implementation

    def _get_api_key(self):
        return self.api_key

    # utils

    def force_manifest_task_result(self, user=None, location=True):
        location_path = f"exports/inventory/{get_random_string(12)}/"
        manifest = {
            "version": 1,
            "format": "PARQUET",
            "tables": {"machine": {"rows": 2, "files": ["machine/machine-00001.parquet"]}},
            "files": {"machine/machine-00001.parquet": {"table": "machine", "rows": 2, "size": 4, "sha256": "…"}},
        }
        if location:
            manifest["location"] = location_path
        tr, _, _ = force_task_result(result={"manifest": manifest}, user=user)
        return tr, manifest, location_path

    # task result

    def test_task_result_unauthorized(self):
        response = self.get(reverse("base_api:task_result", args=(str(uuid.uuid4()),)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_task_result_unknown(self):
        task_id = str(uuid.uuid4())
        response = self.get(reverse("base_api:task_result", args=(task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"id": task_id, "status": "UNKNOWN", "unready": True})

    def test_task_result_unknown_login(self):
        task_id = str(uuid.uuid4())
        self.login()
        response = self.get(reverse("base_api:task_result", args=(task_id,)), include_token=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"id": task_id, "status": "UNKNOWN", "unready": True})

    def test_task_result(self):
        tr, result, _ = force_task_result(user=self.service_account)
        response = self.get(reverse("base_api:task_result", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"id": tr.task_id,
             "name": "zentral.contrib.santa.tasks.export_targets",
             "status": "SUCCESS",
             "unready": False,
             "result": result,
             "download_url": f"/api/task_result/{tr.task_id}/download/"}
        )

    def test_task_result_bad_json(self):
        tr, _, _ = force_task_result(bad_json=True, user=self.service_account)
        response = self.get(reverse("base_api:task_result", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"id": tr.task_id,
             "name": "zentral.contrib.santa.tasks.export_targets",
             "status": "SUCCESS",
             "unready": False}
        )

    def test_task_result_login(self):
        tr, result, _ = force_task_result(user=self.user)
        self.login()
        response = self.get(reverse("base_api:task_result", args=(tr.task_id,)), include_token=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"id": tr.task_id,
             "name": "zentral.contrib.santa.tasks.export_targets",
             "status": "SUCCESS",
             "unready": False,
             "result": result,
             "download_url": f"/api/task_result/{tr.task_id}/download/"}
        )

    def test_task_result_other_user_unknown(self):
        tr, _, _ = force_task_result(user=self.other_user)
        response = self.get(reverse("base_api:task_result", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"id": tr.task_id, "status": "UNKNOWN", "unready": True})

    def test_task_result_other_user_unknown_login(self):
        tr, _, _ = force_task_result(user=self.other_user)
        self.login()
        response = self.get(reverse("base_api:task_result", args=(tr.task_id,)), include_token=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"id": tr.task_id, "status": "UNKNOWN", "unready": True})

    def test_task_result_without_user_unknown(self):
        tr, _, _ = force_task_result()
        response = self.get(reverse("base_api:task_result", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"id": tr.task_id, "status": "UNKNOWN", "unready": True})

    def test_task_result_superuser(self):
        tr, result, _ = force_task_result(user=self.other_user)
        self.client.force_login(self.superuser)
        response = self.get(reverse("base_api:task_result", args=(tr.task_id,)), include_token=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"id": tr.task_id,
             "name": "zentral.contrib.santa.tasks.export_targets",
             "status": "SUCCESS",
             "unready": False,
             "result": result,
             "download_url": f"/api/task_result/{tr.task_id}/download/"}
        )

    def test_task_result_without_user_superuser(self):
        tr, result, _ = force_task_result()
        self.client.force_login(self.superuser)
        response = self.get(reverse("base_api:task_result", args=(tr.task_id,)), include_token=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "SUCCESS")

    def test_task_result_superuser_service_account_unknown(self):
        # a service account is never a superuser, but the flag is only forced on save
        User.objects.filter(pk=self.service_account.pk).update(is_superuser=True)
        tr, _, _ = force_task_result(user=self.other_user)
        response = self.get(reverse("base_api:task_result", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"id": tr.task_id, "status": "UNKNOWN", "unready": True})

    # task result, manifest

    def test_task_result_manifest(self):
        tr, manifest, _ = self.force_manifest_task_result(user=self.service_account)
        response = self.get(reverse("base_api:task_result", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 200)
        expected_manifest = {k: v for k, v in manifest.items() if k != "location"}
        self.assertEqual(
            response.json(),
            {"id": tr.task_id,
             "name": "zentral.contrib.santa.tasks.export_targets",
             "status": "SUCCESS",
             "unready": False,
             "result": {"manifest": expected_manifest},
             "download_url": f"/api/task_result/{tr.task_id}/download/"}
        )

    def test_task_result_manifest_without_location(self):
        tr, manifest, _ = self.force_manifest_task_result(user=self.service_account, location=False)
        response = self.get(reverse("base_api:task_result", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"id": tr.task_id,
             "name": "zentral.contrib.santa.tasks.export_targets",
             "status": "SUCCESS",
             "unready": False,
             "result": {"manifest": manifest}}
        )

    def test_task_result_manifest_not_a_dict(self):
        tr, _, _ = force_task_result(result={"manifest": ["yolo"]}, user=self.service_account)
        response = self.get(reverse("base_api:task_result", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("download_url", response.json())
        self.assertEqual(response.json()["result"], {"manifest": ["yolo"]})

    # task result file download

    def test_result_file_download_unauthorized(self):
        response = self.get(reverse("base_api:task_result_file_download", args=(str(uuid.uuid4()),)),
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_result_file_download_404(self):
        response = self.get(reverse("base_api:task_result_file_download", args=(str(uuid.uuid4()),)))
        self.assertEqual(response.status_code, 404)

    def test_result_file_download_404_login(self):
        self.login()
        response = self.get(reverse("base_api:task_result_file_download", args=(str(uuid.uuid4()),)),
                            include_token=False)
        self.assertEqual(response.status_code, 404)

    def test_result_file_download_bad_json(self):
        tr, _, _ = force_task_result(bad_json=True, user=self.service_account)
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 404)

    def test_result_no_filepath(self):
        tr, _, _ = force_task_result(result={}, user=self.service_account)
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 404)

    def test_result_file_download_not_exists(self):
        tr, result, _ = force_task_result(user=self.service_account)
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 404)

    def test_result_file_download_direct(self):
        tr, result, filepath = force_task_result(user=self.service_account)
        with default_storage.open(filepath, "wb") as f:
            f.write(b"yolo")
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], result["headers"]["Content-Type"])
        self.assertEqual(response.headers["Content-Disposition"], result["headers"]["Content-Disposition"])
        self.assertEqual(b"".join(response.streaming_content), b"yolo")

    def test_result_file_download_other_user_404(self):
        tr, _, filepath = force_task_result(user=self.other_user)
        with default_storage.open(filepath, "wb") as f:
            f.write(b"yolo")
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 404)

    def test_result_file_download_other_user_404_login(self):
        tr, _, filepath = force_task_result(user=self.other_user)
        with default_storage.open(filepath, "wb") as f:
            f.write(b"yolo")
        self.login()
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)),
                            include_token=False)
        self.assertEqual(response.status_code, 404)

    def test_result_file_download_without_user_404(self):
        tr, _, filepath = force_task_result()
        with default_storage.open(filepath, "wb") as f:
            f.write(b"yolo")
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 404)

    def test_result_file_download_superuser(self):
        tr, result, filepath = force_task_result(user=self.other_user)
        with default_storage.open(filepath, "wb") as f:
            f.write(b"yolo")
        self.client.force_login(self.superuser)
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)),
                            include_token=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), b"yolo")

    @patch("base.api_views.file_storage_has_signed_urls")
    def test_result_file_download_redirect_login(self, file_storage_has_signed_urls):
        file_storage_has_signed_urls.return_value = True
        tr, result, filepath = force_task_result(user=self.user)
        self.login()
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)),
                            include_token=False)
        self.assertRedirects(response, f"/{filepath}", fetch_redirect_response=False)

    # task result manifest download

    def test_result_download_manifest(self):
        tr, manifest, _ = self.force_manifest_task_result(user=self.service_account)
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 200)
        key = "machine/machine-00001.parquet"
        expected = {k: v for k, v in manifest.items() if k != "location"}
        expected["files"] = {
            key: {**manifest["files"][key],
                  "download_url": f"/api/task_result/{tr.task_id}/download/?file=machine%2Fmachine-00001.parquet"}
        }
        self.assertEqual(response.json(), expected)

    def test_result_download_manifest_login(self):
        tr, manifest, _ = self.force_manifest_task_result(user=self.user)
        self.login()
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)),
                            include_token=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()["files"]), {"machine/machine-00001.parquet"})

    def test_result_download_manifest_other_user_404(self):
        tr, _, _ = self.force_manifest_task_result(user=self.other_user)
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 404)

    @patch("base.api_views.file_storage_signed_url_expiration")
    @patch("base.api_views.file_storage_has_signed_urls")
    def test_result_download_manifest_signed_urls(self, file_storage_has_signed_urls,
                                                  file_storage_signed_url_expiration):
        file_storage_has_signed_urls.return_value = True
        file_storage_signed_url_expiration.return_value = timedelta(hours=1)
        tr, manifest, location = self.force_manifest_task_result(user=self.service_account)
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 200)
        file_info = response.json()["files"]["machine/machine-00001.parquet"]
        self.assertEqual(file_info["download_url"],
                         f"/api/task_result/{tr.task_id}/download/?file=machine%2Fmachine-00001.parquet")
        self.assertEqual(file_info["url"], f"/{location}machine/machine-00001.parquet")
        expires_at = datetime.strptime(file_info["expires_at"], "%Y-%m-%dT%H:%M:%SZ")
        self.assertLess(abs(expires_at - naive_utcnow() - timedelta(hours=1)), timedelta(minutes=1))

    @patch("base.api_views.file_storage_signed_url_expiration")
    @patch("base.api_views.file_storage_has_signed_urls")
    def test_result_download_manifest_signed_urls_without_expiration(self, file_storage_has_signed_urls,
                                                                     file_storage_signed_url_expiration):
        file_storage_has_signed_urls.return_value = True
        file_storage_signed_url_expiration.return_value = None
        tr, manifest, location = self.force_manifest_task_result(user=self.service_account)
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 200)
        file_info = response.json()["files"]["machine/machine-00001.parquet"]
        self.assertEqual(file_info["url"], f"/{location}machine/machine-00001.parquet")
        self.assertNotIn("expires_at", file_info)

    # task result manifest file download

    def test_result_download_file(self):
        tr, _, location = self.force_manifest_task_result(user=self.service_account)
        default_storage.save(f"{location}machine/machine-00001.parquet", ContentFile(b"yolo"))
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,))
                            + "?file=machine%2Fmachine-00001.parquet")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "application/octet-stream")
        self.assertEqual(response.headers["Content-Disposition"], 'attachment; filename="machine-00001.parquet"')
        self.assertEqual(b"".join(response.streaming_content), b"yolo")

    @patch("base.api_views.file_storage_has_signed_urls")
    def test_result_download_file_redirect(self, file_storage_has_signed_urls):
        file_storage_has_signed_urls.return_value = True
        tr, _, location = self.force_manifest_task_result(user=self.service_account)
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,))
                            + "?file=machine/machine-00001.parquet")
        self.assertRedirects(response, f"/{location}machine/machine-00001.parquet", fetch_redirect_response=False)

    def test_result_download_file_unknown_key_404(self):
        tr, _, location = self.force_manifest_task_result(user=self.service_account)
        # the object exists in the storage, but the manifest does not list it
        default_storage.save(f"{location}other.parquet", ContentFile(b"yolo"))
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)) + "?file=other.parquet")
        self.assertEqual(response.status_code, 404)

    @patch("base.api_views.file_storage_has_signed_urls")
    def test_result_download_file_unknown_key_no_redirect(self, file_storage_has_signed_urls):
        file_storage_has_signed_urls.return_value = True
        tr, _, _ = self.force_manifest_task_result(user=self.service_account)
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)) + "?file=other.parquet")
        self.assertEqual(response.status_code, 404)

    def test_result_download_file_missing_object_404(self):
        tr, _, _ = self.force_manifest_task_result(user=self.service_account)
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,))
                            + "?file=machine%2Fmachine-00001.parquet")
        self.assertEqual(response.status_code, 404)

    def test_result_download_file_single_file_result_404(self):
        tr, _, filepath = force_task_result(user=self.service_account)
        default_storage.save(filepath, ContentFile(b"yolo"))
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)) + "?file=yolo")
        self.assertEqual(response.status_code, 404)

    def test_result_download_file_other_user_404(self):
        tr, _, location = self.force_manifest_task_result(user=self.other_user)
        default_storage.save(f"{location}machine/machine-00001.parquet", ContentFile(b"yolo"))
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,))
                            + "?file=machine%2Fmachine-00001.parquet")
        self.assertEqual(response.status_code, 404)
