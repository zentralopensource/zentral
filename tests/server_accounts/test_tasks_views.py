from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
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
        cls.task_by_user = TaskResult.objects.create(
            task_name='zentral.test.user_task',
            task_id=str(uuid.uuid4()),
            result={},
            date_created=datetime.utcnow() - timedelta(days=1, seconds=10),
            date_done=datetime.utcnow() - timedelta(days=1)
        )
        UserTask.objects.create(
                    user=User.objects.get(id=cls.ui_user.id),
                    task_result=TaskResult.objects.get(id=cls.task_by_user.id)
                )
        cls.task_by_admin = TaskResult.objects.create(
            task_name='zentral.test.admin_task',
            task_id=str(uuid.uuid4()),
            result={},
            date_created=datetime.utcnow() - timedelta(days=1, seconds=10),
            date_done=datetime.utcnow() - timedelta(days=1)
        )

    # auth utils

    def login(self, user):
        self.client.force_login(user)

    # task list

    def test_task_list_user(self):
        self.login(self.ui_user)
        response = self.client.get(reverse("accounts:tasks"))
        self.assertTemplateUsed(response, "accounts/task_list.html")
        self.assertContains(response, self.ui_user.email)
        self.assertEqual(response.context["object_list"].count(), 1)
        self.assertContains(response, 'User Task')

    def test_task_list_admin(self):
        self.login(self.admin_user)
        response = self.client.get(reverse("accounts:tasks"))
        self.assertTemplateUsed(response, "accounts/task_list.html")
        self.assertContains(response, self.admin_user.email)
        self.assertEqual(response.context["object_list"].count(), 2)
        self.assertContains(response, 'Admin Task')

    # task detail

    def test_view_task_get(self):
        self.login(self.ui_user)
        response = self.client.get(reverse("accounts:task", args=(self.task_by_user.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/task_detail.html")
        self.assertContains(response, 'User Task')

    def test_view_task_deny(self):
        self.login(self.ui_user)
        response = self.client.get(reverse("accounts:task", args=(self.task_by_admin.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/task_detail.html")
        self.assertNotContains(response, 'Admin Task')

    def test_view_task_admin(self):
        self.login(self.admin_user)
        response = self.client.get(reverse("accounts:task", args=(self.task_by_admin.task_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/task_detail.html")
        self.assertContains(response, 'Admin Task')
