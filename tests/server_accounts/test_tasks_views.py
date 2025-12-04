from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User, UserTask
from django_celery_results.models import TaskResult

from datetime import datetime, timedelta
import uuid


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class AccountTasksViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # users
        cls.ui_user = User.objects.create_user(
            get_random_string(12),
            "{}@zentral.io".format(get_random_string(12)),
            get_random_string(12),
            is_superuser=False
        )

        cls.admin_user = User.objects.create_user(
            get_random_string(12),
            "{}@zentral.io".format(get_random_string(12)),
            get_random_string(12),
            is_superuser=True
        )

        # Tasks
        cls.task_with_errors = TaskResult.objects.create(
            task_name=None,
            task_id=str(uuid.uuid4()),
            status="FINISHED",
            result=None,
            date_created=None,
            date_done=None
        )
        cls.task_by_user = TaskResult.objects.create(
            task_name='zentral.test.user_task',
            task_id=str(uuid.uuid4()),
            result='{"result_error": "Result.DoesNotExist"}',
            date_created=datetime.utcnow() - timedelta(days=1, seconds=10),
            date_started=datetime.utcnow() - timedelta(days=1, seconds=20),
            date_done=datetime.utcnow() - timedelta(days=1)
        )
        UserTask.objects.create(
                    user=User.objects.get(id=cls.ui_user.id),
                    task_result=TaskResult.objects.get(id=cls.task_by_user.id)
                )
        cls.task_by_admin = TaskResult.objects.create(
            task_name='zentral.test.admin_task',
            task_id=str(uuid.uuid4()),
            result='{"filepath": "export/some_file.csv"}',
            date_created=datetime.utcnow() - timedelta(days=1, seconds=10),
            date_done=datetime.utcnow() - timedelta(days=1)
        )

    # auth utils

    def login(self, user):
        self.client.force_login(user)

    def login_redirect(self, url_name, *args):
        url = reverse("accounts:{}".format(url_name), args=args)
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    # urls

    def test_task_list_redirect(self):
        self.login_redirect("tasks")

    def test_task_list_login(self):
        self.login(self.ui_user)
        response = self.client.get(reverse("accounts:tasks"))
        self.assertEqual(response.status_code, 200)

    def test_task_detail_redirect(self):
        self.login_redirect("task", self.task_by_user.task_id)

    def test_task_detail_login(self):
        self.login(self.ui_user)
        response = self.client.get(reverse("accounts:task", args=(self.task_by_user.task_id,)))
        self.assertEqual(response.status_code, 200)

    # task list

    def test_task_list_user(self):
        self.login(self.ui_user)
        response = self.client.get(reverse("accounts:tasks"))
        self.assertTemplateUsed(response, "accounts/task_list.html")
        self.assertEqual(response.context["object_list"].count(), 1)
        self.assertContains(response, 'User Task')

    def test_task_list_admin(self):
        self.login(self.admin_user)
        response = self.client.get(reverse("accounts:tasks"))
        self.assertTemplateUsed(response, "accounts/task_list.html")
        self.assertEqual(response.context["object_list"].count(), 3)
        self.assertContains(response, 'Admin Task')

    # task detail

    def test_view_task_get(self):
        self.login(self.ui_user)
        response = self.client.get(reverse("accounts:task", args=(self.task_by_user.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/task_detail.html")
        self.assertContains(response, 'User Task')
        self.assertEqual(response.context["time_diff"], self.task_by_user.date_done - self.task_by_user.date_started)

    def test_view_task_deny(self):
        self.login(self.ui_user)
        response = self.client.get(reverse("accounts:task", args=(self.task_by_admin.task_id,)))
        self.assertEqual(response.status_code, 404)

    def test_view_task_with_errors(self):
        self.login(self.admin_user)
        response = self.client.get(reverse("accounts:task", args=(self.task_with_errors.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/task_detail.html")
        self.assertContains(response, '<h3 class="m-0 fs-5 text-secondary">-</h3>')
        # check for Exceptions
        self.assertEqual(response.context["time_diff"], 0)
        self.assertEqual(response.context["result_json"], {})

    def test_view_task_admin(self):
        self.login(self.admin_user)
        response = self.client.get(reverse("accounts:task", args=(self.task_by_admin.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/task_detail.html")
        self.assertContains(response, 'Admin Task')
        # check for download button
        self.assertContains(response, "/api/task_result/%s/download/" % self.task_by_admin.task_id)

    def test_view_task_admin_and_usertask(self):
        self.login(self.admin_user)
        response = self.client.get(reverse("accounts:task", args=(self.task_by_user.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/task_detail.html")
        self.assertContains(response, 'User Task')
        # check for user link
        self.assertContains(response, '<th>User</th>')
        self.assertContains(response, self.ui_user.username)
        # check for result display
        self.assertContains(response, "result_error")

