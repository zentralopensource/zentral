from datetime import datetime
from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.http import http_date
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.munki.models import Configuration, Enrollment


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

    def get(self, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.get(url, **kwargs)

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
             'name': configuration.name,
             'principal_user_detection_domains': [],
             'principal_user_detection_sources': [],
             'updated_at': configuration.updated_at.isoformat(),
             'version': 0},
            response.json()
        )

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
             'name': configuration.name,
             'principal_user_detection_domains': [],
             'principal_user_detection_sources': [],
             'updated_at': configuration.updated_at.isoformat(),
             'version': 0},
            response.json()
        )

    # list enrollments

    def test_get_enrollments_unauthorized(self):
        response = self.get(reverse("munki_api:enrollments"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollments_permission_denied(self):
        response = self.get(reverse("munki_api:enrollments"))
        self.assertEqual(response.status_code, 403)

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
