from functools import reduce
import operator
from unittest.mock import patch
import uuid
from django.contrib.auth.models import Group, Permission
from django.core.files.storage import default_storage
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import APIToken, User
from .utils import force_task_result


class BaseAPIViewsTestCase(TestCase):
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
        cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)

    # utility methods

    def set_permissions(self, *permissions):
        if permissions:
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self.group.permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self.group.permissions.clear()

    def login(self, *permissions):
        self.set_permissions(*permissions)
        self.client.force_login(self.user)

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _make_request(self, method, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["content_type"] = "application/json"
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return method(url, **kwargs)

    def get(self, *args, **kwargs):
        return self._make_request(self.client.get, *args, **kwargs)

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
