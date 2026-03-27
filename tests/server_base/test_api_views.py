from unittest.mock import patch
import uuid

from django.contrib.auth.models import Group
from django.core.files.storage import default_storage
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase

from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
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
        tr, result, _ = force_task_result()
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
        tr, _, _ = force_task_result(bad_json=True)
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
        tr, result, _ = force_task_result()
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
        tr, _, _ = force_task_result(bad_json=True)
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 404)

    def test_result_no_filepath(self):
        tr, _, _ = force_task_result(result={})
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 404)

    def test_result_file_download_not_exists(self):
        tr, result, _ = force_task_result()
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 404)

    def test_result_file_download_direct(self):
        tr, result, filepath = force_task_result()
        with default_storage.open(filepath, "wb") as f:
            f.write(b"yolo")
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], result["headers"]["Content-Type"])
        self.assertEqual(response.headers["Content-Disposition"], result["headers"]["Content-Disposition"])
        self.assertEqual(b"".join(response.streaming_content), b"yolo")

    @patch("base.api_views.file_storage_has_signed_urls")
    def test_result_file_download_redirect_login(self, file_storage_has_signed_urls):
        file_storage_has_signed_urls.return_value = True
        tr, result, filepath = force_task_result()
        self.login()
        response = self.get(reverse("base_api:task_result_file_download", args=(tr.task_id,)),
                            include_token=False)
        self.assertRedirects(response, f"/{filepath}", fetch_redirect_response=False)
