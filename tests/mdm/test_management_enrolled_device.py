from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import MetaBusinessUnit
from .utils import force_dep_enrollment_session, force_ota_enrollment_session, force_user_enrollment_session


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class EnrolledDeviceManagementViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    # utiliy methods

    def _login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _login(self, *permissions):
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
        self.client.force_login(self.user)

    # test enrolled devices

    def test_enrolled_devices_redirect(self):
        self._login_redirect(reverse("mdm:enrolled_devices"))

    def test_enrolled_devices_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:enrolled_devices"))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_devices(self):
        session, device_udid, serial_number = force_dep_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_devices"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_list.html")
        self.assertContains(response, device_udid)
        self.assertContains(response, serial_number)

    # test enrolled device

    def test_enrolled_device_redirect(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login_redirect(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))

    def test_enrolled_device_permission_denied(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        self._login()
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_device_no_enrollment_link(self):
        session, device_udid, serial_number = force_user_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, device_udid)
        self.assertContains(response, serial_number)
        self.assertContains(response, "1 Enrollment session")
        self.assertContains(response, session.get_enrollment().name)
        self.assertNotContains(response, reverse("mdm:user_enrollment", args=(session.get_enrollment().pk,)))

    def test_enrolled_device_enrollment_link(self):
        session, device_udid, serial_number = force_ota_enrollment_session(self.mbu, completed=True)
        self._login("mdm.view_enrolleddevice", "mdm.view_otaenrollment")
        response = self.client.get(reverse("mdm:enrolled_device", args=(session.enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, device_udid)
        self.assertContains(response, serial_number)
        self.assertContains(response, "1 Enrollment session")
        self.assertContains(response, session.get_enrollment().name)
        self.assertContains(response, reverse("mdm:ota_enrollment", args=(session.get_enrollment().pk,)))
