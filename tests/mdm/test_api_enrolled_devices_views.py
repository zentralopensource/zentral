from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.events import FileVaultPRKViewedEvent, RecoveryPasswordViewedEvent
from .utils import force_dep_enrollment_session


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class APIViewsTestCase(TestCase):
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
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu, authenticated=True, completed=True
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device

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

    def get(self, url, include_token=True):
        kwargs = {}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.get(url, **kwargs)

    # enrolled_device_filevault_prk

    def test_enrolled_device_filevault_prk_unauthorized(self):
        response = self.get(reverse("mdm_api:enrolled_device_filevault_prk", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_enrolled_device_filevault_prk_permission_denied(self):
        response = self.get(reverse("mdm_api:enrolled_device_filevault_prk", args=(self.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_filevault_prk_null(self, post_event):
        self.set_permissions("mdm.view_filevault_prk")
        response = self.get(reverse("mdm_api:enrolled_device_filevault_prk", args=(self.enrolled_device.pk,)))
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "filevault_prk": None}
        )
        post_event.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_filevault_prk(self, post_event):
        self.enrolled_device.set_filevault_prk("123456")
        self.enrolled_device.save()
        self.set_permissions("mdm.view_filevault_prk")
        response = self.get(reverse("mdm_api:enrolled_device_filevault_prk", args=(self.enrolled_device.pk,)))
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "filevault_prk": "123456"}
        )
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, FileVaultPRKViewedEvent)
        self.assertEqual(event.metadata.machine_serial_number, self.enrolled_device.serial_number)

    # enrolled_device_filevault_prk

    def test_enrolled_device_recovery_password_unauthorized(self):
        response = self.get(reverse("mdm_api:enrolled_device_recovery_password", args=(self.enrolled_device.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_enrolled_device_recovery_password_permission_denied(self):
        response = self.get(reverse("mdm_api:enrolled_device_recovery_password", args=(self.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_recovery_password_null(self, post_event):
        self.set_permissions("mdm.view_recovery_password")
        response = self.get(reverse("mdm_api:enrolled_device_recovery_password", args=(self.enrolled_device.pk,)))
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "recovery_password": None}
        )
        post_event.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enrolled_device_recovery_password(self, post_event):
        self.enrolled_device.set_recovery_password("123456")
        self.enrolled_device.save()
        self.set_permissions("mdm.view_recovery_password")
        response = self.get(reverse("mdm_api:enrolled_device_recovery_password", args=(self.enrolled_device.pk,)))
        self.assertEqual(
            response.json(),
            {"id": self.enrolled_device.pk,
             "serial_number": self.enrolled_device.serial_number,
             "recovery_password": "123456"}
        )
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, RecoveryPasswordViewedEvent)
        self.assertEqual(event.metadata.machine_serial_number, self.enrolled_device.serial_number)
