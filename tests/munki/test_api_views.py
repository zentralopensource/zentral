from datetime import datetime
from functools import reduce
import operator
from unittest.mock import patch
import uuid
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.http import http_date
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag
from zentral.contrib.munki.models import Configuration, Enrollment, ScriptCheck
from zentral.core.compliance_checks.models import ComplianceCheck
from zentral.core.events.base import AuditEvent
from .utils import force_script_check


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

    def force_configuration(self):
        return Configuration.objects.create(name=get_random_string(12))

    def force_enrollment(self):
        configuration = self.force_configuration()
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        return Enrollment.objects.create(configuration=configuration, secret=enrollment_secret)

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

    def _make_request(self, method, url, data, include_token):
        kwargs = {"content_type": "application/json"}
        if data is not None:
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return method(url, **kwargs)

    def get(self, url, data=None, include_token=True):
        return self._make_request(self.client.get, url, data, include_token)

    def post(self, url, data=None, include_token=True):
        return self._make_request(self.client.post, url, data, include_token)

    def put(self, url, data=None, include_token=True):
        return self._make_request(self.client.put, url, data, include_token)

    def delete(self, url, include_token=True):
        return self._make_request(self.client.delete, url, None, include_token)

    # list configurations

    def test_get_configurations_unauthorized(self):
        response = self.get(reverse("munki_api:configurations"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_configurations_permission_denied(self):
        response = self.get(reverse("munki_api:configurations"))
        self.assertEqual(response.status_code, 403)

    def test_get_configurations(self):
        configuration = self.force_configuration()
        self.set_permissions("munki.view_configuration")
        response = self.get(reverse("munki_api:configurations"))
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            {'auto_failed_install_incidents': False,
             'auto_reinstall_incidents': False,
             'collected_condition_keys': [],
             'created_at': configuration.created_at.isoformat(),
             'description': '',
             'id': configuration.pk,
             'inventory_apps_full_info_shard': 100,
             'managed_installs_sync_interval_days': 7,
             'script_checks_run_interval_seconds': 86400,
             'name': configuration.name,
             'principal_user_detection_domains': [],
             'principal_user_detection_sources': [],
             'updated_at': configuration.updated_at.isoformat(),
             'version': 0},
            response.json()
        )

    def test_get_configurations_by_name(self):
        self.force_configuration()
        configuration = self.force_configuration()
        self.set_permissions("munki.view_configuration")
        response = self.get(reverse("munki_api:configurations"), {"name": configuration.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'auto_failed_install_incidents': False,
              'auto_reinstall_incidents': False,
              'collected_condition_keys': [],
              'created_at': configuration.created_at.isoformat(),
              'description': '',
              'id': configuration.pk,
              'inventory_apps_full_info_shard': 100,
              'managed_installs_sync_interval_days': 7,
              'script_checks_run_interval_seconds': 86400,
              'name': configuration.name,
              'principal_user_detection_domains': [],
              'principal_user_detection_sources': [],
              'updated_at': configuration.updated_at.isoformat(),
              'version': 0}]
        )

    # create configuration

    def test_create_configuration_unauthorized(self):
        response = self.post(reverse("munki_api:configurations"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_configuration_permission_denied(self):
        response = self.post(reverse("munki_api:configurations"), {})
        self.assertEqual(response.status_code, 403)

    def test_create_configuration_required_field(self):
        self.set_permissions("munki.add_configuration")
        response = self.post(reverse("munki_api:configurations"), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'name': ['This field is required.']})

    def test_create_configuration_default_values(self):
        self.set_permissions("munki.add_configuration")
        name = get_random_string(12)
        response = self.post(reverse("munki_api:configurations"), {"name": name})
        self.assertEqual(response.status_code, 201)
        configuration = Configuration.objects.get(name=name)
        self.assertEqual(
            response.json(),
            {'id': configuration.pk,
             'name': name,
             'description': '',
             'inventory_apps_full_info_shard': 100,
             'principal_user_detection_sources': [],
             'principal_user_detection_domains': [],
             'collected_condition_keys': [],
             'managed_installs_sync_interval_days': 7,
             'script_checks_run_interval_seconds': 86400,
             'auto_reinstall_incidents': False,
             'auto_failed_install_incidents': False,
             'version': 0,
             'created_at': configuration.created_at.isoformat(),
             'updated_at': configuration.updated_at.isoformat()}
        )
        self.assertEqual(configuration.name, name)
        self.assertEqual(configuration.description, "")
        self.assertEqual(configuration.inventory_apps_full_info_shard, 100)
        self.assertEqual(configuration.principal_user_detection_sources, [])
        self.assertEqual(configuration.principal_user_detection_domains, [])
        self.assertEqual(configuration.collected_condition_keys, [])
        self.assertEqual(configuration.managed_installs_sync_interval_days, 7)
        self.assertEqual(configuration.script_checks_run_interval_seconds, 86400)
        self.assertFalse(configuration.auto_reinstall_incidents)
        self.assertFalse(configuration.auto_failed_install_incidents)
        self.assertEqual(configuration.version, 0)

    def test_create_configuration(self):
        self.set_permissions("munki.add_configuration")
        name = get_random_string(12)
        response = self.post(
            reverse("munki_api:configurations"),
            {"name": name,
             "description": "Description",
             "inventory_apps_full_info_shard": 50,
             "principal_user_detection_sources": ["google_chrome", "company_portal"],
             "principal_user_detection_domains": ["zentral.io"],
             "collected_condition_keys": ["yolo"],
             "managed_installs_sync_interval_days": 1,
             "script_checks_run_interval_seconds": 86400,
             "auto_reinstall_incidents": True,
             "auto_failed_install_incidents": True}
        )
        self.assertEqual(response.status_code, 201)
        configuration = Configuration.objects.get(name=name)
        self.assertEqual(
            response.json(),
            {'id': configuration.pk,
             'name': name,
             'description': 'Description',
             'inventory_apps_full_info_shard': 50,
             'principal_user_detection_sources': ["google_chrome", "company_portal"],
             'principal_user_detection_domains': ["zentral.io"],
             'collected_condition_keys': ["yolo"],
             'managed_installs_sync_interval_days': 1,
             'script_checks_run_interval_seconds': 86400,
             'auto_reinstall_incidents': True,
             'auto_failed_install_incidents': True,
             'version': 0,
             'created_at': configuration.created_at.isoformat(),
             'updated_at': configuration.updated_at.isoformat()}
        )
        self.assertEqual(configuration.name, name)
        self.assertEqual(configuration.description, "Description")
        self.assertEqual(configuration.inventory_apps_full_info_shard, 50)
        self.assertEqual(configuration.principal_user_detection_sources, ["google_chrome", "company_portal"])
        self.assertEqual(configuration.principal_user_detection_domains, ["zentral.io"])
        self.assertEqual(configuration.collected_condition_keys, ["yolo"])
        self.assertEqual(configuration.managed_installs_sync_interval_days, 1)
        self.assertEqual(configuration.script_checks_run_interval_seconds, 86400)
        self.assertTrue(configuration.auto_reinstall_incidents)
        self.assertTrue(configuration.auto_failed_install_incidents)
        self.assertEqual(configuration.version, 0)

    # get configuration

    def test_get_configuration_unauthorized(self):
        configuration = self.force_configuration()
        response = self.get(reverse("munki_api:configuration", args=(configuration.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_configuration_permission_denied(self):
        configuration = self.force_configuration()
        response = self.get(reverse("munki_api:configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_configuration(self):
        configuration = self.force_configuration()
        self.set_permissions("munki.view_configuration")
        response = self.get(reverse("munki_api:configuration", args=(configuration.pk,)))
        self.assertEqual(
            {'auto_failed_install_incidents': False,
             'auto_reinstall_incidents': False,
             'collected_condition_keys': [],
             'created_at': configuration.created_at.isoformat(),
             'description': '',
             'id': configuration.pk,
             'inventory_apps_full_info_shard': 100,
             'managed_installs_sync_interval_days': 7,
             'script_checks_run_interval_seconds': 86400,
             'name': configuration.name,
             'principal_user_detection_domains': [],
             'principal_user_detection_sources': [],
             'updated_at': configuration.updated_at.isoformat(),
             'version': 0},
            response.json()
        )

    # update configuration

    def test_update_configuration_unauthorized(self):
        configuration = self.force_configuration()
        response = self.put(reverse("munki_api:configuration", args=(configuration.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_configuration_permission_denied(self):
        configuration = self.force_configuration()
        response = self.put(reverse("munki_api:configuration", args=(configuration.pk,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_configuration(self):
        configuration = self.force_configuration()
        self.set_permissions("munki.change_configuration")
        name = get_random_string(12)
        response = self.put(
            reverse("munki_api:configuration", args=(configuration.pk,)),
            {"name": name,
             "description": "Description",
             "inventory_apps_full_info_shard": 50,
             "principal_user_detection_sources": ["google_chrome", "company_portal"],
             "principal_user_detection_domains": ["zentral.io"],
             "collected_condition_keys": ["yolo"],
             "managed_installs_sync_interval_days": 1,
             "script_checks_run_interval_seconds": 86400,
             "auto_reinstall_incidents": True,
             "auto_failed_install_incidents": True}
        )
        self.assertEqual(response.status_code, 200)
        configuration.refresh_from_db()
        self.assertEqual(
            response.json(),
            {'id': configuration.pk,
             'name': name,
             'description': 'Description',
             'inventory_apps_full_info_shard': 50,
             'principal_user_detection_sources': ["google_chrome", "company_portal"],
             'principal_user_detection_domains': ["zentral.io"],
             'collected_condition_keys': ["yolo"],
             'managed_installs_sync_interval_days': 1,
             'script_checks_run_interval_seconds': 86400,
             'auto_reinstall_incidents': True,
             'auto_failed_install_incidents': True,
             'version': 1,
             'created_at': configuration.created_at.isoformat(),
             'updated_at': configuration.updated_at.isoformat()}
        )
        self.assertEqual(configuration.name, name)
        self.assertEqual(configuration.description, "Description")
        self.assertEqual(configuration.inventory_apps_full_info_shard, 50)
        self.assertEqual(configuration.principal_user_detection_sources, ["google_chrome", "company_portal"])
        self.assertEqual(configuration.principal_user_detection_domains, ["zentral.io"])
        self.assertEqual(configuration.collected_condition_keys, ["yolo"])
        self.assertEqual(configuration.managed_installs_sync_interval_days, 1)
        self.assertEqual(configuration.script_checks_run_interval_seconds, 86400)
        self.assertTrue(configuration.auto_reinstall_incidents)
        self.assertTrue(configuration.auto_failed_install_incidents)
        self.assertEqual(configuration.version, 1)

    # delete configuration

    def test_delete_configuration_unauthorized(self):
        configuration = self.force_configuration()
        response = self.delete(reverse("munki_api:configuration", args=(configuration.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_configuration_permission_denied(self):
        configuration = self.force_configuration()
        response = self.delete(reverse("munki_api:configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_configuration(self):
        configuration = self.force_configuration()
        self.set_permissions("munki.delete_configuration")
        response = self.delete(reverse("munki_api:configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(Configuration.objects.filter(pk=configuration.pk).count(), 0)

    # list enrollments

    def test_get_enrollments_unauthorized(self):
        response = self.get(reverse("munki_api:enrollments"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollments_permission_denied(self):
        response = self.get(reverse("munki_api:enrollments"))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_by_configuration_id(self):
        self.force_enrollment()
        enrollment = self.force_enrollment()
        self.set_permissions("munki.view_enrollment")
        response = self.get(reverse('munki_api:enrollments'), {"configuration_id": enrollment.configuration.id})
        self.assertEqual(response.status_code, 200)
        fqdn = settings["api"]["fqdn"]
        self.assertEqual(
            response.json(),
            [{'id': enrollment.pk,
              'configuration': enrollment.configuration.pk,
              'enrolled_machines_count': 0,
              'secret': {
                  'id': enrollment.secret.pk,
                  'secret': enrollment.secret.secret,
                  'meta_business_unit': self.mbu.pk,
                  'tags': [],
                  'serial_numbers': None,
                  'udids': None,
                  'quota': None,
                  'request_count': 0
              },
              'version': 1,
              'package_download_url': f'https://{fqdn}/api/munki/enrollments/{enrollment.pk}/package/',
              'created_at': enrollment.created_at.isoformat(),
              'updated_at': enrollment.updated_at.isoformat()}],
            response.json()
        )

    def test_get_enrollments(self):
        enrollment = self.force_enrollment()
        self.set_permissions("munki.view_enrollment")
        response = self.get(reverse('munki_api:enrollments'))
        self.assertEqual(response.status_code, 200)
        fqdn = settings["api"]["fqdn"]
        self.assertIn(
            {'id': enrollment.pk,
             'configuration': enrollment.configuration.pk,
             'enrolled_machines_count': 0,
             'secret': {
                 'id': enrollment.secret.pk,
                 'secret': enrollment.secret.secret,
                 'meta_business_unit': self.mbu.pk,
                 'tags': [],
                 'serial_numbers': None,
                 'udids': None,
                 'quota': None,
                 'request_count': 0
             },
             'version': 1,
             'package_download_url': f'https://{fqdn}/api/munki/enrollments/{enrollment.pk}/package/',
             'created_at': enrollment.created_at.isoformat(),
             'updated_at': enrollment.updated_at.isoformat()},
            response.json()
        )

    # create enrollment

    def test_create_enrollment_unauthorized(self):
        response = self.post(reverse("munki_api:enrollments"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_enrollment_permission_denied(self):
        response = self.post(reverse("munki_api:enrollments"), {})
        self.assertEqual(response.status_code, 403)

    def test_create_enrollment_required_fields(self):
        self.set_permissions("munki.add_enrollment")
        response = self.post(reverse("munki_api:enrollments"), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'configuration': ['This field is required.'], 'secret': ['This field is required.']}
        )

    def test_create_enrollment(self):
        configuration = self.force_configuration()
        self.set_permissions("munki.add_enrollment")
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(1)]
        serial_numbers = [get_random_string(12) for _ in range(1)]
        uuids = [str(uuid.uuid4()) for _ in range(1)]
        response = self.post(
            reverse("munki_api:enrollments"),
            {'configuration': configuration.pk,
             'secret': {'meta_business_unit': self.mbu.pk,
                        'serial_numbers': serial_numbers,
                        'tags': [t.id for t in tags],
                        'udids': uuids,
                        'quota': 19}}
        )
        self.assertEqual(response.status_code, 201)
        enrollment = configuration.enrollment_set.first()
        fqdn = settings["api"]["fqdn"]
        self.assertEqual(
            response.json(),
            {'id': enrollment.pk,
             'configuration': configuration.pk,
             'enrolled_machines_count': 0,
             'secret': {
                 'id': enrollment.secret.pk,
                 'secret': enrollment.secret.secret,
                 'meta_business_unit': self.mbu.pk,
                 'tags': [t.id for t in tags],
                 'serial_numbers': serial_numbers,
                 'udids': uuids,
                 'quota': 19,
                 'request_count': 0
             },
             'version': 1,
             'package_download_url': f'https://{fqdn}/api/munki/enrollments/{enrollment.pk}/package/',
             'created_at': enrollment.created_at.isoformat(),
             'updated_at': enrollment.updated_at.isoformat()},
            {}
        )

    # get enrollment

    def test_get_enrollment_unauthorized(self):
        enrollment = self.force_enrollment()
        response = self.get(reverse("munki_api:enrollment", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_permission_denied(self):
        enrollment = self.force_enrollment()
        response = self.get(reverse("munki_api:enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_not_found(self):
        self.set_permissions("munki.view_enrollment")
        response = self.get(reverse("munki_api:enrollment", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment(self):
        self.set_permissions("munki.view_enrollment")
        enrollment = self.force_enrollment()
        response = self.get(reverse("munki_api:enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        fqdn = settings["api"]["fqdn"]
        self.assertEqual(
            response.json(),
            {'id': enrollment.pk,
             'configuration': enrollment.configuration.pk,
             'enrolled_machines_count': 0,
             'secret': {
                 'id': enrollment.secret.pk,
                 'secret': enrollment.secret.secret,
                 'meta_business_unit': self.mbu.pk,
                 'tags': [],
                 'serial_numbers': None,
                 'udids': None,
                 'quota': None,
                 'request_count': 0
             },
             'version': 1,
             'package_download_url': f'https://{fqdn}/api/munki/enrollments/{enrollment.pk}/package/',
             'created_at': enrollment.created_at.isoformat(),
             'updated_at': enrollment.updated_at.isoformat()},
        )

    # update enrollment

    def test_update_enrollment_unauthorized(self):
        enrollment = self.force_enrollment()
        response = self.put(reverse("munki_api:enrollment", args=(enrollment.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_enrollment_permission_denied(self):
        enrollment = self.force_enrollment()
        response = self.put(reverse("munki_api:enrollment", args=(enrollment.pk,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_enrollment(self):
        enrollment = self.force_enrollment()
        self.set_permissions("munki.change_enrollment")
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(1)]
        serial_numbers = [get_random_string(12) for _ in range(1)]
        uuids = [str(uuid.uuid4()) for _ in range(1)]
        response = self.put(
            reverse("munki_api:enrollment", args=(enrollment.pk,)),
            {'configuration': enrollment.configuration.pk,
             'secret': {'meta_business_unit': self.mbu.pk,
                        'serial_numbers': serial_numbers,
                        'tags': [t.id for t in tags],
                        'udids': uuids,
                        'quota': 19}}
        )
        self.assertEqual(response.status_code, 200)
        enrollment.refresh_from_db()
        fqdn = settings["api"]["fqdn"]
        self.assertEqual(
            response.json(),
            {'id': enrollment.pk,
             'configuration': enrollment.configuration.pk,
             'enrolled_machines_count': 0,
             'secret': {
                 'id': enrollment.secret.pk,
                 'secret': enrollment.secret.secret,
                 'meta_business_unit': self.mbu.pk,
                 'tags': [t.id for t in tags],
                 'serial_numbers': serial_numbers,
                 'udids': uuids,
                 'quota': 19,
                 'request_count': 0
             },
             'version': 2,
             'package_download_url': f'https://{fqdn}/api/munki/enrollments/{enrollment.pk}/package/',
             'created_at': enrollment.created_at.isoformat(),
             'updated_at': enrollment.updated_at.isoformat()},
            {}
        )

    # delete enrollment

    def test_delete_enrollment_unauthorized(self):
        enrollment = self.force_enrollment()
        response = self.delete(reverse("munki_api:enrollment", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_enrollment_permission_denied(self):
        enrollment = self.force_enrollment()
        response = self.delete(reverse("munki_api:enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_enrollment(self):
        enrollment = self.force_enrollment()
        self.set_permissions("munki.delete_enrollment")
        response = self.delete(reverse("munki_api:enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(Enrollment.objects.filter(pk=enrollment.pk).count(), 0)

    # get enrollment package

    def test_get_enrollment_package_unauthorized(self):
        enrollment = self.force_enrollment()
        response = self.get(reverse("munki_api:enrollment_package", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_package_token_permission_denied(self):
        enrollment = self.force_enrollment()
        response = self.get(reverse("munki_api:enrollment_package", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_package_user_permission_denied(self):
        enrollment = self.force_enrollment()
        self.login()
        response = self.client.get(reverse("munki_api:enrollment_package", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_package_not_found(self):
        self.force_enrollment()
        self.set_permissions("munki.view_enrollment")
        response = self.get(reverse("munki_api:enrollment_package", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment_package_token(self):
        enrollment = self.force_enrollment()
        self.set_permissions("munki.view_enrollment")
        response = self.get(reverse("munki_api:enrollment_package", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/octet-stream")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_munki_enroll.pkg"')
        self.assertEqual(response['Last-Modified'], http_date(enrollment.updated_at.timestamp()))
        self.assertEqual(response['ETag'], f'W/"munki.enrollment-{enrollment.pk}-1"')

    def test_get_enrollment_package_user(self):
        enrollment = self.force_enrollment()
        self.login("munki.view_enrollment")
        response = self.client.get(reverse("munki_api:enrollment_package", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/octet-stream")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_munki_enroll.pkg"')
        self.assertEqual(response['Last-Modified'], http_date(enrollment.updated_at.timestamp()))
        self.assertEqual(response['ETag'], f'W/"munki.enrollment-{enrollment.pk}-1"')

    def test_get_enrollment_package_user_not_modified_etag_header(self):
        enrollment = self.force_enrollment()
        etag = f'W/"munki.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_NONE_MATCH": etag}
        self.login("munki.view_enrollment")
        response = self.client.get(reverse("munki_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    def test_get_enrollment_package_user_not_modified_if_modified_since_header(self):
        enrollment = self.force_enrollment()
        etag = f'W/"munki.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_MODIFIED_SINCE": http_date(enrollment.updated_at.timestamp())}
        self.login("munki.view_enrollment")
        response = self.client.get(reverse("munki_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    def test_get_enrollment_package_user_not_modified_both_headers(self):
        enrollment = self.force_enrollment()
        etag = f'W/"munki.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_NONE_MATCH": etag,
                       "HTTP_IF_MODIFIED_SINCE": http_date(enrollment.updated_at.timestamp())}
        self.login("munki.view_enrollment")
        response = self.client.get(reverse("munki_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    def test_get_enrollment_package_user_etag_mismatch(self):
        enrollment = self.force_enrollment()
        etag = f'W/"munki.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_NONE_MATCH": "YOLO"}
        self.login("munki.view_enrollment")
        response = self.client.get(reverse("munki_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    def test_get_enrollment_package_user_if_modified_since_too_old(self):
        enrollment = self.force_enrollment()
        etag = f'W/"munki.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_MODIFIED_SINCE": http_date(datetime(2001, 1, 1).timestamp())}
        self.login("munki.view_enrollment")
        response = self.client.get(reverse("munki_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    # list script checks

    def test_get_script_checks_unauthorized(self):
        response = self.get(reverse("munki_api:script_checks"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_script_checks_permission_denied(self):
        response = self.get(reverse("munki_api:script_checks"))
        self.assertEqual(response.status_code, 403)

    def test_get_script_check_by_name(self):
        sc = force_script_check()
        force_script_check()
        self.set_permissions("munki.view_scriptcheck")
        response = self.get(reverse('munki_api:script_checks'), {"name": sc.compliance_check.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'id': sc.pk,
              'description': sc.compliance_check.description,
              'expected_result': sc.expected_result,
              'arch_amd64': True,
              'arch_arm64': True,
              'max_os_version': sc.min_os_version,
              'min_os_version': sc.max_os_version,
              'name': sc.compliance_check.name,
              'source': sc.source,
              'tags': [t.pk for t in sc.tags.all()],
              'type': str(sc.type),
              'created_at': sc.created_at.isoformat(),
              'updated_at': sc.updated_at.isoformat(),
              'version': 1}],
        )

    def test_get_script_checks_by_name(self):
        sc = force_script_check()
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(1)]
        sc2 = force_script_check(tags=tags)
        self.set_permissions("munki.view_scriptcheck")
        response = self.get(reverse('munki_api:script_checks'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            sorted(response.json(), key=lambda d: d["id"]),
            [{'id': sc.pk,
              'description': sc.compliance_check.description,
              'expected_result': sc.expected_result,
              'arch_amd64': True,
              'arch_arm64': True,
              'max_os_version': sc.min_os_version,
              'min_os_version': sc.max_os_version,
              'name': sc.compliance_check.name,
              'source': sc.source,
              'tags': [t.pk for t in sc.tags.all()],
              'type': str(sc.type),
              'created_at': sc.created_at.isoformat(),
              'updated_at': sc.updated_at.isoformat(),
              'version': 1},
             {'id': sc2.pk,
              'description': sc2.compliance_check.description,
              'expected_result': sc2.expected_result,
              'arch_amd64': True,
              'arch_arm64': True,
              'max_os_version': sc2.min_os_version,
              'min_os_version': sc2.max_os_version,
              'name': sc2.compliance_check.name,
              'source': sc.source,
              'tags': [tags[0].pk],
              'type': str(sc2.type),
              'created_at': sc2.created_at.isoformat(),
              'updated_at': sc2.updated_at.isoformat(),
              'version': 1}],
        )

    # create script check

    def test_create_script_check_unauthorized(self):
        response = self.post(reverse("munki_api:script_checks"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_script_check_permission_denied(self):
        response = self.post(reverse("munki_api:script_checks"), {})
        self.assertEqual(response.status_code, 403)

    def test_create_script_check_name_conflict(self):
        self.set_permissions("munki.add_scriptcheck")
        sc = force_script_check()
        response = self.post(reverse("munki_api:script_checks"),
                             {"name": sc.compliance_check.name,
                              "type": "ZSH_STR",
                              "source": "echo yolo",
                              "expected_result": "yolo"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'name': ['A Script check with this name already exists.']}
        )

    def test_create_script_check_expected_result_validation_error(self):
        self.set_permissions("munki.add_scriptcheck")
        response = self.post(reverse("munki_api:script_checks"),
                             {"name": get_random_string(12),
                              "type": "ZSH_INT",
                              "source": "echo yolo",
                              "expected_result": "yolo"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'expected_result': ['Invalid integer']}
        )

    def test_create_script_check_no_arch_error(self):
        self.set_permissions("munki.add_scriptcheck")
        response = self.post(reverse("munki_api:script_checks"),
                             {"name": get_random_string(12),
                              "arch_amd64": False,
                              "arch_arm64": False,
                              "type": "ZSH_STR",
                              "source": "echo yolo",
                              "expected_result": "yolo"})
        self.assertEqual(response.status_code, 400)
        err_msg = "This check has to run on at least one architecture"
        self.assertEqual(
            response.json(),
            {"arch_amd64": [err_msg],
             "arch_arm64": [err_msg]}
        )

    def test_create_script_check_invalid_min_os_version(self):
        self.set_permissions("munki.add_scriptcheck")
        response = self.post(reverse("munki_api:script_checks"),
                             {"name": get_random_string(12),
                              "min_os_version": "yolo",
                              "type": "ZSH_STR",
                              "source": "echo yolo",
                              "expected_result": "yolo"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"min_os_version": ["Not a valid OS version"]}
        )

    def test_create_script_check_invalid_max_os_version(self):
        self.set_permissions("munki.add_scriptcheck")
        response = self.post(reverse("munki_api:script_checks"),
                             {"name": get_random_string(12),
                              "max_os_version": "yolo",
                              "type": "ZSH_STR",
                              "source": "echo yolo",
                              "expected_result": "yolo"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"max_os_version": ["Not a valid OS version"]}
        )

    def test_create_script_check_min_os_version_greater_than_max_os_version(self):
        self.set_permissions("munki.add_scriptcheck")
        response = self.post(reverse("munki_api:script_checks"),
                             {"name": get_random_string(12),
                              "min_os_version": "14.1",
                              "max_os_version": "14.0.1",
                              "type": "ZSH_STR",
                              "source": "echo yolo",
                              "expected_result": "yolo"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"min_os_version": ["Should be smaller than the max OS version"]}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_script_check(self, post_event):
        self.set_permissions("munki.add_scriptcheck")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("munki_api:script_checks"),
                                 {"name": name,
                                  "source": "echo yolo",
                                  "expected_result": "yolo"})
        self.assertEqual(response.status_code, 201)
        script_check = ScriptCheck.objects.get(compliance_check__name=name)
        self.assertEqual(script_check.compliance_check.name, name)
        self.assertEqual(script_check.compliance_check.description, "")
        self.assertEqual(script_check.compliance_check.version, 1)
        self.assertEqual(script_check.type, ScriptCheck.Type.ZSH_STR)
        self.assertEqual(script_check.source, "echo yolo")
        self.assertEqual(script_check.expected_result, "yolo")
        self.assertTrue(script_check.arch_amd64)
        self.assertTrue(script_check.arch_arm64)
        self.assertEqual(script_check.min_os_version, "")
        self.assertEqual(script_check.max_os_version, "")
        self.assertEqual(
            response.json(),
            {'id': script_check.pk,
             'description': "",
             'expected_result': "yolo",
             'arch_amd64': True,
             'arch_arm64': True,
             'max_os_version': "",
             'min_os_version': "",
             'name': name,
             'source': "echo yolo",
             'tags': [],
             'type': "ZSH_STR",
             'created_at': script_check.created_at.isoformat(),
             'updated_at': script_check.updated_at.isoformat(),
             'version': 1}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "munki.scriptcheck",
                 "pk": str(script_check.pk),
                 "new_value": {
                     "pk": script_check.pk,
                     "compliance_check": {
                         "pk": script_check.compliance_check.pk,
                         "name": name,
                         "model": "MunkiScriptCheck",
                         "description": "",
                         "version": 1,
                     },
                     "type": "ZSH_STR",
                     "source": "echo yolo",
                     "expected_result": "yolo",
                     "tags": [],
                     "arch_amd64": True,
                     "arch_arm64": True,
                     "created_at": script_check.created_at,
                     "updated_at": script_check.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"munki_script_check": [str(script_check.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["munki", "zentral"])
        self.assertEqual(len(callbacks), 1)

    # get script check

    def test_get_script_check_unauthorized(self):
        sc = force_script_check()
        response = self.get(reverse("munki_api:script_check", args=(sc.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_script_check_permission_denied(self):
        sc = force_script_check()
        response = self.get(reverse("munki_api:script_check", args=(sc.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_script_check(self):
        sc = force_script_check()
        self.set_permissions("munki.view_scriptcheck")
        response = self.get(reverse("munki_api:script_check", args=(sc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'id': sc.pk,
             'description': sc.compliance_check.description,
             'expected_result': sc.expected_result,
             'arch_amd64': True,
             'arch_arm64': True,
             'max_os_version': sc.min_os_version,
             'min_os_version': sc.max_os_version,
             'name': sc.compliance_check.name,
             'source': sc.source,
             'tags': [t.pk for t in sc.tags.all()],
             'type': str(sc.type),
             'created_at': sc.created_at.isoformat(),
             'updated_at': sc.updated_at.isoformat(),
             'version': 1}
        )

    # update script check

    def test_update_script_check_unauthorized(self):
        sc = force_script_check()
        response = self.put(reverse("munki_api:script_check", args=(sc.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_script_check_permission_denied(self):
        sc = force_script_check()
        response = self.put(reverse("munki_api:script_check", args=(sc.pk,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_script_check_name_conflict(self):
        sc = force_script_check()
        sc2 = force_script_check()
        self.set_permissions("munki.change_scriptcheck")
        response = self.put(reverse("munki_api:script_check", args=(sc.pk,)),
                            {"name": sc2.compliance_check.name,
                             "type": "ZSH_BOOL",
                             "source": "echo true",
                             "expected_result": "true"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'name': ['A Script check with this name already exists.']}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_script_check(self, post_event):
        script_check = force_script_check()
        prev_value = script_check.serialize_for_event()
        self.set_permissions("munki.change_scriptcheck")
        name = get_random_string(12)
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(1)]
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("munki_api:script_check", args=(script_check.pk,)),
                                {"name": name,
                                 "description": "yolo",
                                 "type": "ZSH_BOOL",
                                 "source": "echo true",
                                 "expected_result": "true",
                                 "arch_amd64": False,
                                 "arch_arm64": True,
                                 "min_os_version": "14",
                                 "max_os_version": "15",
                                 "tags": [t.pk for t in tags],
                                 })
        self.assertEqual(response.status_code, 200)
        script_check2 = ScriptCheck.objects.get(compliance_check__name=name)
        self.assertEqual(script_check, script_check2)
        self.assertEqual(script_check.compliance_check, script_check2.compliance_check)
        script_check.refresh_from_db()
        self.assertEqual(script_check.compliance_check.name, name)
        self.assertEqual(script_check.compliance_check.description, "yolo")
        self.assertEqual(script_check.compliance_check.version, 2)
        self.assertEqual(script_check.type, ScriptCheck.Type.ZSH_BOOL)
        self.assertEqual(script_check.source, "echo true")
        self.assertEqual(script_check.expected_result, "true")
        self.assertFalse(script_check.arch_amd64)
        self.assertTrue(script_check.arch_arm64)
        self.assertEqual(script_check.min_os_version, "14")
        self.assertEqual(script_check.max_os_version, "15")
        self.assertEqual(list(script_check.tags.all()), tags)
        self.assertEqual(
            response.json(),
            {'id': script_check.pk,
             'description': "yolo",
             'expected_result': "true",
             'arch_amd64': False,
             'arch_arm64': True,
             'max_os_version': "15",
             'min_os_version': "14",
             'name': name,
             'source': "echo true",
             'tags': [tag.pk for tag in tags],
             'type': "ZSH_BOOL",
             'created_at': script_check.created_at.isoformat(),
             'updated_at': script_check.updated_at.isoformat(),
             'version': 2}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "munki.scriptcheck",
                 "pk": str(script_check.pk),
                 "prev_value": prev_value,
                 "new_value": {
                     "pk": script_check.pk,
                     "compliance_check": {
                         "pk": script_check.compliance_check.pk,
                         "name": name,
                         "model": "MunkiScriptCheck",
                         "description": "yolo",
                         "version": 2,
                     },
                     "type": "ZSH_BOOL",
                     "source": "echo true",
                     "expected_result": "true",
                     "min_os_version": "14",
                     "max_os_version": "15",
                     "tags": [{"pk": tag.pk, "name": tag.name} for tag in tags],
                     "arch_amd64": False,
                     "arch_arm64": True,
                     "created_at": script_check.created_at,
                     "updated_at": script_check.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"munki_script_check": [str(script_check.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["munki", "zentral"])
        self.assertEqual(len(callbacks), 1)

    # delete script check

    def test_delete_script_check_unauthorized(self):
        sc = force_script_check()
        response = self.delete(reverse("munki_api:script_check", args=(sc.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_script_check_permission_denied(self):
        sc = force_script_check()
        response = self.delete(reverse("munki_api:script_check", args=(sc.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_script_check(self, post_event):
        script_check = force_script_check()
        prev_pk = script_check.pk
        prev_name = script_check.compliance_check.name
        prev_value = script_check.serialize_for_event()
        self.set_permissions("munki.delete_scriptcheck")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("munki_api:script_check", args=(script_check.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertFalse(ScriptCheck.objects.filter(pk=prev_pk).exists())
        self.assertFalse(ComplianceCheck.objects.filter(name=prev_name).exists())
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "munki.scriptcheck",
                 "pk": str(prev_pk),
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"munki_script_check": [str(prev_pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["munki", "zentral"])
        self.assertEqual(len(callbacks), 1)
