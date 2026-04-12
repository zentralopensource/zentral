from datetime import datetime, time
from unittest.mock import patch
from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase

from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from zentral.contrib.inventory.models import Tag
from zentral.contrib.mdm.models import SoftwareUpdateEnforcement
from zentral.core.events.base import AuditEvent
from .utils import force_blueprint, force_software_update_enforcement


class MDMSoftwareUpdateEnforcementsAPIViewsTestCase(TestCase, LoginCase, RequestCase):
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
        return "mdm_api"

    # RequestCase implementation

    def _get_api_key(self):
        return self.api_key

    # list software update enforcements

    def test_list_software_update_enforcements_unauthorized(self):
        response = self.get(reverse("mdm_api:software_update_enforcements"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_software_update_enforcements_permission_denied(self):
        response = self.get(reverse("mdm_api:software_update_enforcements"))
        self.assertEqual(response.status_code, 403)

    def test_list_software_update_enforcements(self):
        sue = force_software_update_enforcement()
        self.set_permissions("mdm.view_softwareupdateenforcement")
        response = self.get(reverse("mdm_api:software_update_enforcements"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'id': sue.pk,
              'name': sue.name,
              'details_url': '',
              'platforms': ['macOS'],
              'tags': [],
              'max_os_version': '17.1.2',
              'delay_days': 14,
              'local_time': '09:30:00',
              'os_version': '',
              'build_version': '',
              'local_datetime': None,
              'created_at': sue.created_at.isoformat(),
              'updated_at': sue.updated_at.isoformat()}],
        )

    def test_list_software_update_enforcements_name_filter(self):
        force_software_update_enforcement()
        sue = force_software_update_enforcement()
        self.set_permissions("mdm.view_softwareupdateenforcement")
        response = self.get(reverse("mdm_api:software_update_enforcements"), data={"name": sue.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'id': sue.pk,
              'name': sue.name,
              'details_url': '',
              'platforms': ['macOS'],
              'tags': [],
              'max_os_version': '17.1.2',
              'delay_days': 14,
              'local_time': '09:30:00',
              'os_version': '',
              'build_version': '',
              'local_datetime': None,
              'created_at': sue.created_at.isoformat(),
              'updated_at': sue.updated_at.isoformat()}],
        )

    # get software update enforcement

    def test_get_software_update_enforcement_unauthorized(self):
        sue = force_software_update_enforcement()
        response = self.get(reverse("mdm_api:software_update_enforcement", args=(sue.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_software_update_enforcement_permission_denied(self):
        sue = force_software_update_enforcement()
        response = self.get(reverse("mdm_api:blueprint", args=(sue.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_software_update_enforcement(self):
        force_software_update_enforcement()
        sue = force_software_update_enforcement()
        self.set_permissions("mdm.view_softwareupdateenforcement")
        response = self.get(reverse("mdm_api:software_update_enforcement", args=(sue.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'id': sue.pk,
             'name': sue.name,
             'details_url': '',
             'platforms': ['macOS'],
             'tags': [],
             'max_os_version': '17.1.2',
             'delay_days': 14,
             'local_time': '09:30:00',
             'os_version': '',
             'build_version': '',
             'local_datetime': None,
             'created_at': sue.created_at.isoformat(),
             'updated_at': sue.updated_at.isoformat()}
        )

    # create software update enforcement

    def test_create_software_update_enforcement_unauthorized(self):
        response = self.post(reverse("mdm_api:software_update_enforcements"),
                             {"name": get_random_string(12)},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_software_update_enforcement_permission_denied(self):
        response = self.post(reverse("mdm_api:software_update_enforcements"),
                             {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 403)

    def test_create_software_update_enforcement_bad_max_os_version(self):
        self.set_permissions("mdm.add_softwareupdateenforcement")
        name = get_random_string(12)
        response = self.post(reverse("mdm_api:software_update_enforcements"),
                             {"name": name,
                              "platforms": ["iOS", "tvOS"],
                              "max_os_version": "ABC"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'max_os_version': ['Not a valid OS version']}
        )

    def test_create_software_update_enforcement_bad_os_version(self):
        self.set_permissions("mdm.add_softwareupdateenforcement")
        name = get_random_string(12)
        response = self.post(reverse("mdm_api:software_update_enforcements"),
                             {"name": name,
                              "platforms": ["macOS"],
                              "os_version": "ABC",
                              "local_datetime": "2023-11-28T09:30"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'os_version': ['Not a valid OS version']}
        )

    def test_create_software_update_enforcement_max_os_version_or_os_version_both_set_error(self):
        self.set_permissions("mdm.add_softwareupdateenforcement")
        name = get_random_string(12)
        response = self.post(reverse("mdm_api:software_update_enforcements"),
                             {"name": name,
                              "platforms": ["macOS"],
                              "max_os_version": "15",
                              "os_version": "14.1"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'non_field_errors': ['os_version and max_os_version cannot be both set']}
        )

    def test_create_software_update_enforcement_max_os_version_or_os_version_required(self):
        self.set_permissions("mdm.add_softwareupdateenforcement")
        name = get_random_string(12)
        response = self.post(reverse("mdm_api:software_update_enforcements"),
                             {"name": name,
                              "platforms": ["macOS"],
                              "local_datetime": "2023-11-28T09:30"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'non_field_errors': ['os_version or max_os_version are required']}
        )

    def test_create_software_update_enforcement_one_time_required_fields(self):
        self.set_permissions("mdm.add_softwareupdateenforcement")
        name = get_random_string(12)
        response = self.post(reverse("mdm_api:software_update_enforcements"),
                             {"name": name,
                              "platforms": ["macOS"],
                              "os_version": "14.1"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'local_datetime': ['This field is required if os_version is used']},
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_software_update_enforcement_latest(self, post_event):
        self.set_permissions("mdm.add_softwareupdateenforcement")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:software_update_enforcements"),
                                 {"name": name,
                                  "platforms": ["macOS"],
                                  "max_os_version": "15"})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        sue = SoftwareUpdateEnforcement.objects.get(name=name)
        self.assertEqual(sue.name, name)
        self.assertEqual(sue.platforms, ["macOS"])
        self.assertEqual(sue.max_os_version, "15")
        self.assertEqual(sue.local_time, time(9, 30))
        self.assertEqual(sue.delay_days, 14)
        self.assertEqual(sue.details_url, "")
        self.assertEqual(sue.os_version, "")
        self.assertEqual(sue.build_version, "")
        self.assertIsNone(sue.local_datetime)
        self.assertEqual(
            response.json(),
            {'id': sue.pk,
             'name': name,
             'details_url': '',
             'platforms': ['macOS'],
             'tags': [],
             'max_os_version': '15',
             'delay_days': 14,
             'local_time': '09:30:00',
             'os_version': '',
             'build_version': '',
             'local_datetime': None,
             'created_at': sue.created_at.isoformat(),
             'updated_at': sue.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.softwareupdateenforcement",
                 "pk": str(sue.pk),
                 "new_value": {
                     "pk": sue.pk,
                     "name": name,
                     "platforms": ["macOS"],
                     "tags": [],
                     "max_os_version": "15",
                     "delay_days": 14,
                     "local_time": "09:30:00",
                     "created_at": sue.created_at,
                     "updated_at": sue.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_software_update_enforcement": [str(sue.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_software_update_enforcement_one_time(self, post_event):
        self.set_permissions("mdm.add_softwareupdateenforcement")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:software_update_enforcements"),
                                 {"name": name,
                                  "platforms": ["macOS"],
                                  "os_version": "14.1.1",
                                  "local_datetime": "2023-11-28T09:30"})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        sue = SoftwareUpdateEnforcement.objects.get(name=name)
        self.assertEqual(sue.name, name)
        self.assertEqual(sue.details_url, "")
        self.assertEqual(sue.platforms, ["macOS"])
        self.assertEqual(sue.os_version, "14.1.1")
        self.assertEqual(sue.build_version, "")
        self.assertEqual(sue.local_datetime, datetime(2023, 11, 28, 9, 30))
        self.assertEqual(sue.max_os_version, "")
        self.assertIsNone(sue.delay_days)
        self.assertIsNone(sue.local_time)
        self.assertEqual(
            response.json(),
            {'id': sue.pk,
             'name': name,
             'details_url': '',
             'platforms': ["macOS"],
             'tags': [],
             'max_os_version': '',
             'delay_days': None,
             'local_time': None,
             'os_version': '14.1.1',
             'build_version': '',
             'local_datetime': '2023-11-28T09:30:00',
             'created_at': sue.created_at.isoformat(),
             'updated_at': sue.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.softwareupdateenforcement",
                 "pk": str(sue.pk),
                 "new_value": {
                     "pk": sue.pk,
                     "name": name,
                     "platforms": ["macOS"],
                     "tags": [],
                     "os_version": "14.1.1",
                     "local_datetime": "2023-11-28T09:30:00",
                     "created_at": sue.created_at,
                     "updated_at": sue.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_software_update_enforcement": [str(sue.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # update software update enforcement

    def test_update_software_update_enforcement_unauthorized(self):
        sue = force_software_update_enforcement()
        response = self.put(reverse("mdm_api:software_update_enforcement", args=(sue.pk,)),
                            {"name": get_random_string(12),
                             "max_os_version": "15"},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_software_update_enforcement_permission_denied(self):
        sue = force_software_update_enforcement()
        response = self.put(reverse("mdm_api:software_update_enforcement", args=(sue.pk,)),
                            {"name": get_random_string(12),
                             "max_os_version": "15"})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_software_update_enforcement_latest(self, post_event):
        sue = force_software_update_enforcement()
        prev_value = sue.serialize_for_event()
        self.set_permissions("mdm.change_softwareupdateenforcement")
        new_name = get_random_string(12)
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(1)]
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("mdm_api:software_update_enforcement", args=(sue.pk,)),
                                {"name": new_name,
                                 "details_url": "https://www.example.com",
                                 "platforms": ["macOS"],
                                 "tags": [t.pk for t in tags],
                                 "max_os_version": "18.1.2",
                                 "delay_days": 3,
                                 "local_time": "11:11"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        sue.refresh_from_db()
        self.assertEqual(sue.name, new_name)
        self.assertEqual(sue.details_url, "https://www.example.com")
        self.assertEqual(sue.platforms, ["macOS"])
        self.assertEqual(list(sue.tags.all()), tags)
        self.assertEqual(sue.max_os_version, "18.1.2")
        self.assertEqual(sue.delay_days, 3)
        self.assertEqual(sue.local_time, time(11, 11))
        self.assertEqual(sue.os_version, "")
        self.assertEqual(sue.build_version, "")
        self.assertIsNone(sue.local_datetime)
        self.assertEqual(
            response.json(),
            {'id': sue.pk,
             'name': new_name,
             'details_url': 'https://www.example.com',
             'platforms': ['macOS'],
             'tags': [t.pk for t in tags],
             'max_os_version': '18.1.2',
             'delay_days': 3,
             'local_time': '11:11:00',
             'os_version': '',
             'build_version': '',
             'local_datetime': None,
             'created_at': sue.created_at.isoformat(),
             'updated_at': sue.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.softwareupdateenforcement",
                 "pk": str(sue.pk),
                 "new_value": {
                     "pk": sue.pk,
                     "name": new_name,
                     "details_url": "https://www.example.com",
                     "platforms": ["macOS"],
                     "tags": [{"pk": t.pk, "name": t.name} for t in tags],
                     "max_os_version": "18.1.2",
                     "delay_days": 3,
                     "local_time": "11:11:00",
                     "created_at": sue.created_at,
                     "updated_at": sue.updated_at
                 },
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_software_update_enforcement": [str(sue.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_software_update_enforcement_one_time(self, post_event):
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(1)]
        sue = force_software_update_enforcement(details_url="https://www.example.com", tags=tags)
        prev_value = sue.serialize_for_event()
        self.set_permissions("mdm.change_softwareupdateenforcement")
        new_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("mdm_api:software_update_enforcement", args=(sue.pk,)),
                                {"name": new_name,
                                 "details_url": "",
                                 "platforms": ["iOS"],
                                 "tags": [],
                                 "os_version": "18.1.2",
                                 "build_version": "29B12",
                                 "local_datetime": "2028-12-12T11:11"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        sue.refresh_from_db()
        self.assertEqual(sue.name, new_name)
        self.assertEqual(sue.details_url, "")
        self.assertEqual(sue.platforms, ["iOS"])
        self.assertEqual(sue.tags.count(), 0)
        self.assertEqual(sue.os_version, "18.1.2")
        self.assertEqual(sue.build_version, "29B12")
        self.assertEqual(sue.local_datetime, datetime(2028, 12, 12, 11, 11))
        self.assertEqual(sue.max_os_version, "")
        self.assertIsNone(sue.delay_days)
        self.assertIsNone(sue.local_time)
        self.assertEqual(
            response.json(),
            {'id': sue.pk,
             'name': new_name,
             'details_url': '',
             'platforms': ['iOS'],
             'tags': [],
             'max_os_version': '',
             'delay_days': None,
             'local_time': None,
             'os_version': '18.1.2',
             'build_version': '29B12',
             'local_datetime': '2028-12-12T11:11:00',
             'created_at': sue.created_at.isoformat(),
             'updated_at': sue.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.softwareupdateenforcement",
                 "pk": str(sue.pk),
                 "new_value": {
                     "pk": sue.pk,
                     "name": new_name,
                     "platforms": ["iOS"],
                     "tags": [],
                     "os_version": "18.1.2",
                     "build_version": "29B12",
                     "local_datetime": "2028-12-12T11:11:00",
                     "created_at": sue.created_at,
                     "updated_at": sue.updated_at
                 },
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_software_update_enforcement": [str(sue.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # delete software update enforcement

    def test_delete_software_update_enforcement_unauthorized(self):
        sue = force_software_update_enforcement()
        response = self.delete(reverse("mdm_api:software_update_enforcement", args=(sue.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_software_update_enforcement_permission_denied(self):
        sue = force_software_update_enforcement()
        response = self.delete(reverse("mdm_api:software_update_enforcement", args=(sue.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_software_update_enforcement_cannot_be_deleted(self):
        sue = force_software_update_enforcement()
        force_blueprint(software_update_enforcement=sue)
        self.set_permissions("mdm.delete_softwareupdateenforcement")
        response = self.delete(reverse("mdm_api:software_update_enforcement", args=(sue.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This software update enforcement cannot be deleted"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_software_update_enforcement(self, post_event):
        sue = force_software_update_enforcement()
        prev_value = sue.serialize_for_event()
        self.set_permissions("mdm.delete_softwareupdateenforcement")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:software_update_enforcement", args=(sue.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(SoftwareUpdateEnforcement.objects.filter(name=sue.name).count(), 0)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.softwareupdateenforcement",
                 "pk": str(sue.pk),
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_software_update_enforcement": [str(sue.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
