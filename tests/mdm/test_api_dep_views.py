from functools import reduce
import operator
from unittest.mock import patch
from urllib.parse import urlencode
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.dep_client import DEPClientError
from zentral.contrib.mdm.events import DEPDeviceDisownedEvent
from .utils import force_dep_device, force_dep_enrollment, force_dep_virtual_server


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class APIViewsTestCase(TestCase):
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
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

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

    def _make_query(self, verb, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["content_type"] = "application/json"
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return getattr(self.client, verb)(url, **kwargs)

    def get(self, url, include_token=True):
        return self._make_query("get", url, include_token=include_token)

    def post(self, url, include_token=True):
        return self._make_query("post", url, include_token=include_token)

    def put(self, url, data=None, include_token=True):
        return self._make_query("put", url, data=data, include_token=include_token)

    # dep_virtual_server_sync_devices

    def test_sa_dep_virtual_server_sync_devices_unauthorized(self):
        dep_server = force_dep_virtual_server()
        response = self.post(reverse("mdm_api:dep_virtual_server_sync_devices", args=(dep_server.pk,)),
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_sa_dep_virtual_server_sync_devices_permission_denied(self):
        dep_server = force_dep_virtual_server()
        response = self.post(reverse("mdm_api:dep_virtual_server_sync_devices", args=(dep_server.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_sa_dep_virtual_server_sync_devices(self):
        dep_server = force_dep_virtual_server()
        self.set_permissions("mdm.view_depvirtualserver")
        response = self.post(reverse("mdm_api:dep_virtual_server_sync_devices", args=(dep_server.pk,)))
        self.assertEqual(response.status_code, 201)
        self.assertEqual(sorted(response.json().keys()), ['task_id', 'task_result_url'])

    def test_user_dep_virtual_server_sync_devices_unauthorized(self):
        dep_server = force_dep_virtual_server()
        response = self.client.post(reverse("mdm_api:dep_virtual_server_sync_devices", args=(dep_server.pk,)))
        self.assertEqual(response.status_code, 401)

    def test_user_dep_virtual_server_sync_devices_permission_denied(self):
        dep_server = force_dep_virtual_server()
        self.login()
        response = self.client.post(reverse("mdm_api:dep_virtual_server_sync_devices", args=(dep_server.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_user_dep_virtual_server_sync_devices(self):
        dep_server = force_dep_virtual_server()
        self.login("mdm.view_depvirtualserver")
        response = self.client.post(reverse("mdm_api:dep_virtual_server_sync_devices", args=(dep_server.pk,)))
        self.assertEqual(response.status_code, 201)
        self.assertEqual(sorted(response.json().keys()), ['task_id', 'task_result_url'])

    # list dep devices

    def test_list_dep_devices_unauthorized(self):
        response = self.get(reverse("mdm_api:dep_devices"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_dep_devices_permission_denied(self):
        response = self.get(reverse("mdm_api:dep_devices"))
        self.assertEqual(response.status_code, 403)

    def test_list_dep_devices_by_enrollment(self):
        self.set_permissions("mdm.view_depdevice")
        force_dep_device()  # filtered out
        dep_device = force_dep_device()
        dep_device.enrollment = force_dep_enrollment(self.mbu)
        dep_device.save()
        response = self.get(reverse("mdm_api:dep_devices")
                            + "?" + urlencode({"enrollment": dep_device.enrollment.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [
                 {'asset_tag': dep_device.asset_tag,
                  'color': 'SPACE GRAY',
                  'created_at': dep_device.created_at.isoformat(),
                  'description': 'IPHONE X SPACE GRAY 64GB-ZDD',
                  'device_assigned_by': 'support@zentral.com',
                  'device_assigned_date': dep_device.device_assigned_date.isoformat(),
                  'device_family': 'iPhone',
                  'disowned_at': None,
                  'enrollment': dep_device.enrollment.pk,
                  'id': dep_device.pk,
                  'last_op_date': dep_device.last_op_date.isoformat(),
                  'last_op_type': 'added',
                  'model': 'iPhone X',
                  'os': 'iOS',
                  'profile_push_time': None,
                  'profile_status': 'empty',
                  'profile_uuid': None,
                  'serial_number': dep_device.serial_number,
                  'updated_at': dep_device.updated_at.isoformat(),
                  'virtual_server': dep_device.virtual_server.pk}
             ]}
        )

    def test_list_dep_devices_by_serial_number(self):
        self.set_permissions("mdm.view_depdevice")
        force_dep_device()  # filtered out
        dep_device = force_dep_device()
        response = self.get(reverse("mdm_api:dep_devices")
                            + "?" + urlencode({"serial_number": dep_device.serial_number}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [
                 {'asset_tag': dep_device.asset_tag,
                  'color': 'SPACE GRAY',
                  'created_at': dep_device.created_at.isoformat(),
                  'description': 'IPHONE X SPACE GRAY 64GB-ZDD',
                  'device_assigned_by': 'support@zentral.com',
                  'device_assigned_date': dep_device.device_assigned_date.isoformat(),
                  'device_family': 'iPhone',
                  'disowned_at': None,
                  'enrollment': None,
                  'id': dep_device.pk,
                  'last_op_date': dep_device.last_op_date.isoformat(),
                  'last_op_type': 'added',
                  'model': 'iPhone X',
                  'os': 'iOS',
                  'profile_push_time': None,
                  'profile_status': 'empty',
                  'profile_uuid': None,
                  'serial_number': dep_device.serial_number,
                  'updated_at': dep_device.updated_at.isoformat(),
                  'virtual_server': dep_device.virtual_server.pk}
             ]}
        )

    def test_list_dep_devices_by_virtual_server(self):
        self.set_permissions("mdm.view_depdevice")
        force_dep_device()  # filtered out
        dep_device = force_dep_device()
        response = self.get(reverse("mdm_api:dep_devices")
                            + "?" + urlencode({"virtual_server": dep_device.virtual_server.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [
                 {'asset_tag': dep_device.asset_tag,
                  'color': 'SPACE GRAY',
                  'created_at': dep_device.created_at.isoformat(),
                  'description': 'IPHONE X SPACE GRAY 64GB-ZDD',
                  'device_assigned_by': 'support@zentral.com',
                  'device_assigned_date': dep_device.device_assigned_date.isoformat(),
                  'device_family': 'iPhone',
                  'disowned_at': None,
                  'enrollment': None,
                  'id': dep_device.pk,
                  'last_op_date': dep_device.last_op_date.isoformat(),
                  'last_op_type': 'added',
                  'model': 'iPhone X',
                  'os': 'iOS',
                  'profile_push_time': None,
                  'profile_status': 'empty',
                  'profile_uuid': None,
                  'serial_number': dep_device.serial_number,
                  'updated_at': dep_device.updated_at.isoformat(),
                  'virtual_server': dep_device.virtual_server.pk}
             ]}
        )

    def test_list_dep_devices_ordering(self):
        self.set_permissions("mdm.view_depdevice")
        force_dep_device()  # filtered out
        dep_device = force_dep_device()
        force_dep_device()  # filtered out
        response = self.get(reverse("mdm_api:dep_devices")
                            + "?" + urlencode({"ordering": "-created_at",
                                               "limit": 1,
                                               "offset": 1}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'count': 3,
             'next': 'http://testserver/api/mdm/dep/devices/?limit=1&offset=2&ordering=-created_at',
             'previous': 'http://testserver/api/mdm/dep/devices/?limit=1&ordering=-created_at',
             'results': [
                 {'asset_tag': dep_device.asset_tag,
                  'color': 'SPACE GRAY',
                  'created_at': dep_device.created_at.isoformat(),
                  'description': 'IPHONE X SPACE GRAY 64GB-ZDD',
                  'device_assigned_by': 'support@zentral.com',
                  'device_assigned_date': dep_device.device_assigned_date.isoformat(),
                  'device_family': 'iPhone',
                  'disowned_at': None,
                  'enrollment': None,
                  'id': dep_device.pk,
                  'last_op_date': dep_device.last_op_date.isoformat(),
                  'last_op_type': 'added',
                  'model': 'iPhone X',
                  'os': 'iOS',
                  'profile_push_time': None,
                  'profile_status': 'empty',
                  'profile_uuid': None,
                  'serial_number': dep_device.serial_number,
                  'updated_at': dep_device.updated_at.isoformat(),
                  'virtual_server': dep_device.virtual_server.pk}
             ]}
        )

    # get dep device

    def test_get_dep_device_unauthorized(self):
        dep_device = force_dep_device()
        response = self.get(reverse("mdm_api:dep_device", args=(dep_device.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_dep_device_permission_denied(self):
        dep_device = force_dep_device()
        response = self.get(reverse("mdm_api:dep_device", args=(dep_device.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_dep_device(self):
        dep_device = force_dep_device()
        self.set_permissions("mdm.view_depdevice")
        response = self.get(reverse("mdm_api:dep_device", args=(dep_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'asset_tag': dep_device.asset_tag,
             'color': 'SPACE GRAY',
             'created_at': dep_device.created_at.isoformat(),
             'description': 'IPHONE X SPACE GRAY 64GB-ZDD',
             'device_assigned_by': 'support@zentral.com',
             'device_assigned_date': dep_device.device_assigned_date.isoformat(),
             'device_family': 'iPhone',
             'disowned_at': None,
             'enrollment': None,
             'id': dep_device.pk,
             'last_op_date': dep_device.last_op_date.isoformat(),
             'last_op_type': 'added',
             'model': 'iPhone X',
             'os': 'iOS',
             'profile_push_time': None,
             'profile_status': 'empty',
             'profile_uuid': None,
             'serial_number': dep_device.serial_number,
             'updated_at': dep_device.updated_at.isoformat(),
             'virtual_server': dep_device.virtual_server.pk}
        )

    # update dep device

    def test_update_dep_device_unauthorized(self):
        dep_device = force_dep_device()
        response = self.put(reverse("mdm_api:dep_device", args=(dep_device.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_dep_device_permission_denied(self):
        dep_device = force_dep_device()
        response = self.put(reverse("mdm_api:dep_device", args=(dep_device.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.mdm.serializers.assign_dep_device_profile")
    def test_update_dep_device(self, assign_dep_device_profile):
        dep_device = force_dep_device()
        enrollment = force_dep_enrollment(self.mbu)
        self.set_permissions("mdm.change_depdevice")
        response = self.put(reverse("mdm_api:dep_device", args=(dep_device.pk,)),
                            data={"enrollment": enrollment.pk})
        self.assertEqual(response.status_code, 200)
        dep_device.refresh_from_db()
        self.assertEqual(
            response.json(),
            {'asset_tag': dep_device.asset_tag,
             'color': 'SPACE GRAY',
             'created_at': dep_device.created_at.isoformat(),
             'description': 'IPHONE X SPACE GRAY 64GB-ZDD',
             'device_assigned_by': 'support@zentral.com',
             'device_assigned_date': dep_device.device_assigned_date.isoformat(),
             'device_family': 'iPhone',
             'disowned_at': None,
             'enrollment': enrollment.pk,
             'id': dep_device.pk,
             'last_op_date': dep_device.last_op_date.isoformat(),
             'last_op_type': 'added',
             'model': 'iPhone X',
             'os': 'iOS',
             'profile_push_time': None,
             'profile_status': 'empty',
             'profile_uuid': None,
             'serial_number': dep_device.serial_number,
             'updated_at': dep_device.updated_at.isoformat(),
             'virtual_server': dep_device.virtual_server.pk}
        )
        assign_dep_device_profile.assert_called_once_with(dep_device, enrollment)

    @patch("zentral.contrib.mdm.serializers.assign_dep_device_profile")
    def test_update_dep_device_error(self, assign_dep_device_profile):
        assign_dep_device_profile.side_effect = DEPClientError("YOLO")
        dep_device = force_dep_device()
        enrollment = force_dep_enrollment(self.mbu)
        self.set_permissions("mdm.change_depdevice")
        response = self.put(reverse("mdm_api:dep_device", args=(dep_device.pk,)),
                            data={"enrollment": enrollment.pk})
        self.assertEqual(response.status_code, 400)
        dep_device.refresh_from_db()
        self.assertEqual(
            response.json(),
            {'enrollment': 'Could not assign enrollment to device'},
        )
        assign_dep_device_profile.assert_called_once_with(dep_device, enrollment)

    # disown dep device

    def test_disown_dep_device_unauthorized(self):
        dep_device = force_dep_device()
        response = self.post(reverse("mdm_api:disown_dep_device", args=(dep_device.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_disown_dep_device_permission_denied(self):
        dep_device = force_dep_device()
        response = self.post(reverse("mdm_api:disown_dep_device", args=(dep_device.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_disown_dep_device_login_permission_denied(self):
        self.login()
        dep_device = force_dep_device()
        response = self.post(reverse("mdm_api:disown_dep_device", args=(dep_device.pk,)), include_token=False)
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_disown_dep_device_failed(self, send_request, post_event):
        self.set_permissions("mdm.disown_depdevice")
        dep_device = force_dep_device()
        send_request.return_value = {"devices": {dep_device.serial_number: "FAILED"}}
        response = self.post(reverse("mdm_api:disown_dep_device", args=(dep_device.pk,)))
        self.assertEqual(response.json(), {"result": "FAILED"})
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, DEPDeviceDisownedEvent)
        self.assertEqual(event.metadata.machine_serial_number, dep_device.serial_number)
        self.assertEqual(event.payload, {"result": "FAILED"})
        dep_device.refresh_from_db()
        self.assertIsNone(dep_device.disowned_at)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_disown_dep_device_serial_number_error(self, send_request, post_event):
        self.set_permissions("mdm.disown_depdevice")
        dep_device = force_dep_device()
        send_request.return_value = {"devices": {"YOLO": "FAILED"}}
        response = self.post(reverse("mdm_api:disown_dep_device", args=(dep_device.pk,)))
        self.assertEqual(response.json(), {"error": "Could not find result for device"})
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, DEPDeviceDisownedEvent)
        self.assertEqual(event.metadata.machine_serial_number, dep_device.serial_number)
        self.assertEqual(event.payload, {"error": "Could not find result for device"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_disown_dep_device_unknown_result_error(self, send_request, post_event):
        self.set_permissions("mdm.disown_depdevice")
        dep_device = force_dep_device()
        send_request.return_value = {"devices": {dep_device.serial_number: "YOLO"}}
        response = self.post(reverse("mdm_api:disown_dep_device", args=(dep_device.pk,)))
        self.assertEqual(response.json(), {"error": "Unknown result"})
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, DEPDeviceDisownedEvent)
        self.assertEqual(event.metadata.machine_serial_number, dep_device.serial_number)
        self.assertEqual(event.payload, {"error": "Unknown result"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_disown_dep_device_success(self, send_request, post_event):
        self.set_permissions("mdm.disown_depdevice")
        dep_device = force_dep_device()
        send_request.return_value = {"devices": {dep_device.serial_number: "SUCCESS"}}
        response = self.post(reverse("mdm_api:disown_dep_device", args=(dep_device.pk,)))
        self.assertEqual(response.json(), {"result": "SUCCESS"})
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, DEPDeviceDisownedEvent)
        self.assertEqual(event.metadata.machine_serial_number, dep_device.serial_number)
        self.assertEqual(event.payload, {"result": "SUCCESS"})
        dep_device.refresh_from_db()
        self.assertIsNotNone(dep_device.disowned_at)
        self.assertEqual(send_request.call_args_list[0].args, ("devices/disown", "POST"))
        self.assertEqual(send_request.call_args_list[0].kwargs, {'json': {'devices': [dep_device.serial_number]}})
