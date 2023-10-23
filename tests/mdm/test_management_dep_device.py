from datetime import datetime
from functools import reduce
import operator
from unittest.mock import Mock, patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import DEPDevice
from .utils import force_dep_device, force_dep_enrollment


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class DEPDeviceManagementViewsTestCase(TestCase):
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

    # test DEP devices

    def test_dep_devices_redirect(self):
        self._login_redirect(reverse("mdm:dep_devices"))

    def test_dep_devices_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:dep_devices"))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.mdm.views.management.DEPDeviceListView.get_paginate_by")
    def test_dep_devices(self, get_paginate_by):
        get_paginate_by.return_value = 1
        devices = [force_dep_device() for _ in range(3)]
        self._login("mdm.view_depdevice")
        response = self.client.get(reverse("mdm:dep_devices"), {"page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depdevice_list.html")
        self.assertNotContains(response, '<li class="active">Search</li>')
        self.assertContains(response, "Devices (3)")
        self.assertContains(response, "page 2 of 3")
        for idx, device in enumerate(devices):
            if idx != 1:
                self.assertNotContains(response, device.serial_number)
            else:
                self.assertContains(response, device.serial_number)

    def test_dep_devices_serial_number_search_redirect(self):
        device = force_dep_device()
        self._login("mdm.view_depdevice")
        response = self.client.get(
            reverse("mdm:dep_devices"),
            {"q": device.serial_number[1:-1],
             "device_family": "iPhone"},
            follow=True
        )
        self.assertTemplateUsed(response, "mdm/depdevice_detail.html")
        self.assertEqual(response.context["object"], device)

    def test_dep_devices_server_search(self):
        device1 = force_dep_device()
        device2 = force_dep_device()
        device3 = force_dep_device(server=device2.virtual_server)
        self._login("mdm.view_depdevice")
        response = self.client.get(reverse("mdm:dep_devices"), {"server": device2.virtual_server.pk})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<li class="breadcrumb-item active">Search</li>')
        self.assertTemplateUsed(response, "mdm/depdevice_list.html")
        self.assertContains(response, "Devices (2)")
        self.assertContains(response, "page 1 of 1")
        self.assertNotContains(response, device1.serial_number)
        self.assertContains(response, device2.serial_number)
        self.assertContains(response, device3.serial_number)

    def test_dep_devices_enrollment_search(self):
        device1 = force_dep_device()
        device2 = force_dep_device(profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED, mbu=self.mbu)
        device3 = force_dep_device(profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED, enrollment=device2.enrollment)
        self._login("mdm.view_depdevice")
        response = self.client.get(reverse("mdm:dep_devices"), {"enrollment": device2.enrollment.pk})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<li class="breadcrumb-item active">Search</li>')
        self.assertTemplateUsed(response, "mdm/depdevice_list.html")
        self.assertContains(response, "Devices (2)")
        self.assertContains(response, "page 1 of 1")
        self.assertNotContains(response, device1.serial_number)
        self.assertContains(response, device2.serial_number)
        self.assertContains(response, device3.serial_number)

    def test_dep_devices_deleted_not_included_search(self):
        device1 = force_dep_device(
            op_type=DEPDevice.OP_TYPE_DELETED,
            profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED,
            mbu=self.mbu,
        )
        device2 = force_dep_device(profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED, enrollment=device1.enrollment)
        device3 = force_dep_device(profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED, enrollment=device1.enrollment)
        self._login("mdm.view_depdevice")
        response = self.client.get(reverse("mdm:dep_devices"), {"enrollment": device1.enrollment.pk})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<li class="breadcrumb-item active">Search</li>')
        self.assertTemplateUsed(response, "mdm/depdevice_list.html")
        self.assertContains(response, "Devices (2)")
        self.assertContains(response, "page 1 of 1")
        self.assertNotContains(response, device1.serial_number)
        self.assertNotContains(response, "DELETED")
        self.assertContains(response, device2.serial_number)
        self.assertContains(response, device3.serial_number)

    def test_dep_devices_deleted_included_search(self):
        device1 = force_dep_device(
            op_type=DEPDevice.OP_TYPE_DELETED,
            profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED,
            mbu=self.mbu,
        )
        device2 = force_dep_device(profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED, enrollment=device1.enrollment)
        device3 = force_dep_device(profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED, enrollment=device1.enrollment)
        self._login("mdm.view_depdevice")
        response = self.client.get(reverse("mdm:dep_devices"),
                                   {"enrollment": device1.enrollment.pk,
                                    "include_deleted": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<li class="breadcrumb-item active">Search</li>')
        self.assertTemplateUsed(response, "mdm/depdevice_list.html")
        self.assertContains(response, "Devices (3)")
        self.assertContains(response, "page 1 of 1")
        self.assertContains(response, "DELETED")
        self.assertContains(response, device1.serial_number)
        self.assertContains(response, device2.serial_number)
        self.assertContains(response, device3.serial_number)

    # test DEP device

    def test_dep_device_redirect(self):
        device = force_dep_device()
        self._login_redirect(reverse("mdm:dep_device", args=(device.pk,)))

    def test_dep_device_permission_denied(self):
        device = force_dep_device()
        self._login()
        response = self.client.get(reverse("mdm:dep_device", args=(device.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_dep_device_no_links(self):
        device = force_dep_device(profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED, mbu=self.mbu)
        self._login("mdm.view_depdevice")
        response = self.client.get(reverse("mdm:dep_device", args=(device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depdevice_detail.html")
        self.assertContains(response, device.serial_number)
        self.assertContains(response, device.virtual_server.name)
        self.assertNotContains(response, device.virtual_server.get_absolute_url())
        self.assertContains(response, device.enrollment.name)
        self.assertNotContains(response, device.enrollment.get_absolute_url())
        self.assertNotContains(response, reverse("mdm:assign_dep_device_profile", args=(device.pk,)))
        self.assertNotContains(response, reverse("mdm:refresh_dep_device", args=(device.pk,)))

    def test_dep_device_links(self):
        device = force_dep_device(profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED, mbu=self.mbu)
        self._login("mdm.view_depdevice", "mdm.change_depdevice",
                    "mdm.view_depvirtualserver", "mdm.view_depenrollment")
        response = self.client.get(reverse("mdm:dep_device", args=(device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depdevice_detail.html")
        self.assertContains(response, device.serial_number)
        self.assertContains(response, device.virtual_server.name)
        self.assertContains(response, device.virtual_server.get_absolute_url())
        self.assertContains(response, device.enrollment.name)
        self.assertContains(response, device.enrollment.get_absolute_url())
        self.assertContains(response, reverse("mdm:assign_dep_device_profile", args=(device.pk,)))
        self.assertContains(response, reverse("mdm:refresh_dep_device", args=(device.pk,)))

    # test assign profile

    def test_assign_profile_redirect(self):
        device = force_dep_device()
        self._login_redirect(reverse("mdm:assign_dep_device_profile", args=(device.pk,)))

    def test_assign_profile_permission_denied(self):
        device = force_dep_device()
        self._login()
        response = self.client.get(reverse("mdm:assign_dep_device_profile", args=(device.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_assign_profile_get(self):
        enrollment1 = force_dep_enrollment(self.mbu)
        enrollment2 = force_dep_enrollment(self.mbu)
        device = force_dep_device(server=enrollment1.virtual_server)
        self._login("mdm.change_depdevice")
        response = self.client.get(reverse("mdm:assign_dep_device_profile", args=(device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, enrollment1.name)
        self.assertNotContains(response, enrollment2.name)
        self.assertTemplateUsed(response, "mdm/depdevice_form.html")

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_assign_profile_post_ok(self, from_dep_virtual_server):
        enrollment = force_dep_enrollment(self.mbu)
        device = force_dep_device(server=enrollment.virtual_server)
        client = Mock()
        client.assign_profile.return_value = {"devices": {device.serial_number: "SUCCESS"}}
        client.get_devices.return_value = {
            device.serial_number: {
                "color": device.color,
                "description": device.description,
                "device_assigned_by": device.device_assigned_by,
                "device_assigned_date": device.device_assigned_date.isoformat(),
                "device_family": device.device_family,
                "model": device.model,
                "last_op_date": device.last_op_date,
                "last_op_type": device.last_op_type,
                "os": device.os,
                "profile_assign_time": '2023-06-17T15:41:06Z',
                "profile_status": DEPDevice.PROFILE_STATUS_ASSIGNED,
                "profile_uuid": str(enrollment.uuid).upper().replace("-", ""),
                "serial_number": device.serial_number,
            }
        }
        from_dep_virtual_server.return_value = client
        self._login("mdm.change_depdevice", "mdm.view_depdevice")
        response = self.client.post(
            reverse("mdm:assign_dep_device_profile", args=(device.pk,)),
            {"enrollment": enrollment.pk},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depdevice_detail.html")
        device.refresh_from_db()
        self.assertEqual(device.enrollment, enrollment)
        self.assertEqual(device.profile_uuid, enrollment.uuid)
        self.assertEqual(device.profile_assign_time, datetime(2023, 6, 17, 15, 41, 6))
        from_dep_virtual_server.assert_called_once_with(device.virtual_server)
        client.assign_profile.assert_called_once_with(enrollment.uuid, [device.serial_number])
        client.get_devices.assert_called_once_with([device.serial_number])

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_assign_profile_post_err(self, from_dep_virtual_server):
        enrollment = force_dep_enrollment(self.mbu)
        device = force_dep_device(server=enrollment.virtual_server)
        client = Mock()
        client.assign_profile.return_value = {"devices": {device.serial_number: "YOLO"}}
        from_dep_virtual_server.return_value = client
        self._login("mdm.change_depdevice")
        response = self.client.post(
            reverse("mdm:assign_dep_device_profile", args=(device.pk,)),
            {"enrollment": enrollment.pk},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depdevice_form.html")
        device.refresh_from_db()
        self.assertIsNone(device.enrollment)
        self.assertFormError(
            response.context["form"], None,
            f"Could not assign profile {enrollment.uuid} to device {device.serial_number}: YOLO"
        )
        from_dep_virtual_server.assert_called_once_with(device.virtual_server)
        client.assign_profile.assert_called_once_with(enrollment.uuid, [device.serial_number])

    # test refresh

    def test_refresh_login_redirect(self):
        device = force_dep_device()
        self._login_redirect(reverse("mdm:refresh_dep_device", args=(device.pk,)))

    def test_refresh_permission_denied(self):
        device = force_dep_device()
        self._login()
        response = self.client.post(reverse("mdm:refresh_dep_device", args=(device.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_refresh_deleted(self, from_dep_virtual_server):
        client = Mock()
        client.get_devices.return_value = {"devices": {}}
        from_dep_virtual_server.return_value = client
        device = force_dep_device()
        self.assertFalse(device.is_deleted())
        self._login("mdm.change_depdevice", "mdm.view_depdevice")
        response = self.client.post(reverse("mdm:refresh_dep_device", args=(device.pk,)), follow=True)
        self.assertContains(response, "Could not find the device.")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depdevice_detail.html")
        device.refresh_from_db()
        self.assertTrue(device.is_deleted())

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_refresh(self, from_dep_virtual_server):
        device = force_dep_device()
        client = Mock()
        client.get_devices.return_value = {
            device.serial_number: {
                'color': 'SPACE GRAY',
                'description': 'IPHONE X SPACE GRAY 64GB-ZDD',
                'device_assigned_by': 'support@zentral.com',
                'device_assigned_date': '2023-01-10T19:09:22Z',
                'device_family': 'iPhone',
                'model': 'iPhone 14333',
                'os': 'iOS',
                'profile_status': 'empty',
                'serial_number': device.serial_number
            }
        }
        from_dep_virtual_server.return_value = client
        self.assertFalse(device.is_deleted())
        self._login("mdm.change_depdevice", "mdm.view_depdevice")
        response = self.client.post(reverse("mdm:refresh_dep_device", args=(device.pk,)), follow=True)
        self.assertContains(response, "DEP device refreshed.")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depdevice_detail.html")
        device.refresh_from_db()
        self.assertFalse(device.is_deleted())
        self.assertEqual(device.model, "iPhone 14333")
