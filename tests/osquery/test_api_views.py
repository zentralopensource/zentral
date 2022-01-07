from datetime import datetime
from functools import reduce
import json
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.http import http_date
from django.test import TestCase
from rest_framework.authtoken.models import Token
from accounts.models import User
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from zentral.contrib.osquery.models import Configuration, DistributedQuery, Enrollment, Pack, PackQuery, Query


class APIViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(),
            email="{}@zentral.io".format(get_random_string()),
            is_service_account=True
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string())
        cls.group = Group.objects.create(name=get_random_string())
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        Token.objects.get_or_create(user=cls.service_account)
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string())
        cls.mbu.create_enrollment_business_unit()

    def force_configuration(self):
        return Configuration.objects.create(name=get_random_string())

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

    def set_pack_endpoint_put_permissions(self):
        self.set_permissions(
            "osquery.add_pack",
            "osquery.change_pack",
            "osquery.add_packquery",
            "osquery.add_query",
            "osquery.change_packquery",
            "osquery.delete_packquery"
        )

    def set_pack_endpoint_delete_permissions(self):
        self.set_permissions(
            "osquery.delete_pack",
            "osquery.delete_packquery",
        )

    def login(self, *permissions):
        self.set_permissions(*permissions)
        self.client.force_login(self.user)

    def get(self, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.service_account.auth_token.key}"
        return self.client.get(url, **kwargs)

    def post(self, url, include_token=True):
        kwargs = {}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.service_account.auth_token.key}"
        return self.client.post(url, **kwargs)

    def post_json_data(self, url, data, include_token=True):
        kwargs = {'content_type': 'application/json',
                  'data': data}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.service_account.auth_token.key}"
        return self.client.post(url, **kwargs)

    def put_data(self, url, data, content_type, include_token=True):
        kwargs = {"content_type": content_type}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.service_account.auth_token.key}"
        return self.client.put(url, data, **kwargs)

    def delete(self, url, include_token=True):
        kwargs = {}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.service_account.auth_token.key}"
        return self.client.delete(url, **kwargs)

    def put_json_data(self, url, data, include_token=True):
        content_type = "application/json"
        data = json.dumps(data)
        return self.put_data(url, data, content_type, include_token)

    # list configurations

    def test_get_configurations_unauthorized(self):
        response = self.get(reverse("osquery_api:configurations"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_configurations_permission_denied(self):
        response = self.get(reverse("osquery_api:configurations"))
        self.assertEqual(response.status_code, 403)

    def test_get_configurations(self):
        config = self.force_configuration()
        self.set_permissions("osquery.view_configuration")
        response = self.get(reverse('osquery_api:configurations'), data={"name": config.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data,
                         [{"id": config.pk,
                           "name": config.name,
                           'description': "",
                           "inventory": True,
                           "inventory_apps": False,
                           "inventory_interval": 86400,
                           "options": {},
                           "created_at": config.created_at.isoformat(),
                           "updated_at": config.updated_at.isoformat()
                           }])

    # get configuration

    def test_get_configuration_unauthorized(self):
        configuration = self.force_configuration()
        response = self.get(reverse("osquery_api:configuration", args=(configuration.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_configuration_permission_denied(self):
        configuration = self.force_configuration()
        response = self.get(reverse("osquery_api:configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_configuration(self):
        configuration = self.force_configuration()
        self.set_permissions("osquery.view_configuration")
        response = self.get(reverse('osquery_api:configuration', args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(
            response.json(),
            {'id': configuration.pk,
             'name': configuration.name,
             'description': "",
             "inventory": True,
             "inventory_apps": False,
             "inventory_interval": 86400,
             "options": {},
             "created_at": configuration.created_at.isoformat(),
             "updated_at": configuration.updated_at.isoformat()}
        )

    # create configuration

    def test_create_configuration(self):
        self.set_permissions("osquery.add_configuration")
        response = self.post_json_data(reverse('osquery_api:configurations'), {'name': 'Configuration0'})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Configuration.objects.filter(name='Configuration0').count(), 1)
        configuration = Configuration.objects.get(name="Configuration0")
        self.assertEqual(configuration.name, 'Configuration0')

    # update configuration

    def test_update_configuration(self):
        config = self.force_configuration()
        new_name = get_random_string()
        data = {'name': new_name}
        self.set_permissions("osquery.change_configuration")
        response = self.put_json_data(reverse('osquery_api:configuration', args=(config.pk,)), data)
        self.assertEqual(response.status_code, 200)
        config.refresh_from_db()
        self.assertEqual(config.name, new_name)

    def test_update_configuration_name_exists(self):
        config0 = self.force_configuration()
        config1 = self.force_configuration()
        data = {'name': config0.name}
        self.set_permissions("osquery.change_configuration")
        response = self.put_json_data(reverse('osquery_api:configuration', args=(config1.pk,)), data)
        self.assertEqual(response.status_code, 400)
        response_j = response.json()
        self.assertEqual(response_j["name"][0], "configuration with this name already exists.")

    # delete configuration

    def test_delete_configuration(self):
        config = self.force_configuration()
        self.set_permissions("osquery.delete_configuration")
        response = self.delete(reverse('osquery_api:configuration', args=(config.pk,)))
        self.assertEqual(response.status_code, 204)

    def test_delete_configuration_error(self):
        config = self.force_configuration()
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        Enrollment.objects.create(configuration=config, secret=enrollment_secret)
        self.set_permissions("osquery.delete_configuration")
        response = self.delete(reverse('osquery_api:configuration', args=(config.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This configuration cannot be deleted"])

    # list enrollments

    def test_get_enrollments_unauthorized(self):
        response = self.get(reverse("osquery_api:enrollments"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollments_permission_denied(self):
        response = self.get(reverse("osquery_api:enrollments"))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollments(self):
        enrollment = self.force_enrollment()
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse('osquery_api:enrollments'))
        self.assertEqual(response.status_code, 200)
        fqdn = settings["api"]["fqdn"]
        self.assertIn(
            {'id': enrollment.pk,
             'configuration': enrollment.configuration.pk,
             'enrolled_machines_count': 0,
             'osquery_release': '',
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
             'package_download_url': f'https://{fqdn}/api/osquery/enrollments/{enrollment.pk}/package/',
             'powershell_script_download_url': f'https://{fqdn}/api/osquery/'
                                               f'enrollments/{enrollment.pk}/powershell_script/',
             'script_download_url': f'https://{fqdn}/api/osquery/enrollments/{enrollment.pk}/script/'},
            response.json()
        )

    # get enrollment

    def test_get_enrollment_unauthorized(self):
        response = self.get(reverse("osquery_api:enrollment", args=(1213028133,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_permission_denied(self):
        response = self.get(reverse("osquery_api:enrollment", args=(1213028133,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_not_found(self):
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse("osquery_api:enrollment", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment(self):
        self.set_permissions("osquery.view_enrollment")
        enrollment = self.force_enrollment()
        response = self.get(reverse("osquery_api:enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        fqdn = settings["api"]["fqdn"]
        self.assertEqual(
            response.json(),
            {'id': enrollment.pk,
             'configuration': enrollment.configuration.pk,
             'enrolled_machines_count': 0,
             'osquery_release': '',
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
             'package_download_url': f'https://{fqdn}/api/osquery/enrollments/{enrollment.pk}/package/',
             'powershell_script_download_url': f'https://{fqdn}/api/osquery/'
                                               f'enrollments/{enrollment.pk}/powershell_script/',
             'script_download_url': f'https://{fqdn}/api/osquery/enrollments/{enrollment.pk}/script/'},
        )

    # get enrollment package

    def test_get_enrollment_package_unauthorized(self):
        enrollment = self.force_enrollment()
        response = self.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_package_token_permission_denied(self):
        enrollment = self.force_enrollment()
        response = self.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_package_user_permission_denied(self):
        enrollment = self.force_enrollment()
        self.login()
        response = self.client.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_package_not_found(self):
        self.force_enrollment()
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse("osquery_api:enrollment_package", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment_package_token(self):
        enrollment = self.force_enrollment()
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/octet-stream")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_enroll.pkg"')
        self.assertEqual(response['Last-Modified'], http_date(enrollment.updated_at.timestamp()))
        self.assertEqual(response['ETag'], f'W/"osquery.enrollment-{enrollment.pk}-1"')

    def test_get_enrollment_package_user(self):
        enrollment = self.force_enrollment()
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/octet-stream")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_enroll.pkg"')
        self.assertEqual(response['Last-Modified'], http_date(enrollment.updated_at.timestamp()))
        self.assertEqual(response['ETag'], f'W/"osquery.enrollment-{enrollment.pk}-1"')

    def test_get_enrollment_package_user_not_modified_etag_header(self):
        enrollment = self.force_enrollment()
        etag = f'W/"osquery.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_NONE_MATCH": etag}
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    def test_get_enrollment_package_user_not_modified_if_modified_since_header(self):
        enrollment = self.force_enrollment()
        etag = f'W/"osquery.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_MODIFIED_SINCE": http_date(enrollment.updated_at.timestamp())}
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    def test_get_enrollment_package_user_not_modified_both_headers(self):
        enrollment = self.force_enrollment()
        etag = f'W/"osquery.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_NONE_MATCH": etag,
                       "HTTP_IF_MODIFIED_SINCE": http_date(enrollment.updated_at.timestamp())}
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 304)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    def test_get_enrollment_package_user_etag_mismatch(self):
        enrollment = self.force_enrollment()
        etag = f'W/"osquery.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_NONE_MATCH": "YOLO"}
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    def test_get_enrollment_package_user_if_modified_since_too_old(self):
        enrollment = self.force_enrollment()
        etag = f'W/"osquery.enrollment-{enrollment.pk}-1"'
        last_modified = http_date(enrollment.updated_at.timestamp())
        req_headers = {"HTTP_IF_MODIFIED_SINCE": http_date(datetime(2001, 1, 1).timestamp())}
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_package", args=(enrollment.pk,)), **req_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Last-Modified'], last_modified)
        self.assertEqual(response['ETag'], etag)

    # get enrollment powershell script

    def test_get_enrollment_powershell_script_unauthorized(self):
        enrollment = self.force_enrollment()
        response = self.get(reverse("osquery_api:enrollment_powershell_script", args=(enrollment.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_powershell_script_token_permission_denied(self):
        enrollment = self.force_enrollment()
        response = self.get(reverse("osquery_api:enrollment_powershell_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_powershell_script_user_permission_denied(self):
        enrollment = self.force_enrollment()
        self.login()
        response = self.client.get(reverse("osquery_api:enrollment_powershell_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_powershell_script_not_found(self):
        self.force_enrollment()
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse("osquery_api:enrollment_powershell_script", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment_powershell_script_token(self):
        enrollment = self.force_enrollment()
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse("osquery_api:enrollment_powershell_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "text/plain")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_setup.ps1"')

    def test_get_enrollment_powershell_script_user(self):
        enrollment = self.force_enrollment()
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_powershell_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "text/plain")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_setup.ps1"')

    # get enrollment script

    def test_get_enrollment_script_unauthorized(self):
        enrollment = self.force_enrollment()
        response = self.get(reverse("osquery_api:enrollment_script", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_script_token_permission_denied(self):
        enrollment = self.force_enrollment()
        response = self.get(reverse("osquery_api:enrollment_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_script_user_permission_denied(self):
        enrollment = self.force_enrollment()
        self.login()
        response = self.client.get(reverse("osquery_api:enrollment_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_script_not_found(self):
        self.force_enrollment()
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse("osquery_api:enrollment_script", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment_script_token(self):
        enrollment = self.force_enrollment()
        self.set_permissions("osquery.view_enrollment")
        response = self.get(reverse("osquery_api:enrollment_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "text/x-shellscript")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_setup.sh"')

    def test_get_enrollment_script_user(self):
        enrollment = self.force_enrollment()
        self.login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery_api:enrollment_script", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "text/x-shellscript")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_setup.sh"')

    # create enrollment

    def test_create_enrollment(self):
        config = self.force_configuration()
        self.set_permissions("osquery.add_enrollment")
        response = self.post_json_data(
            reverse('osquery_api:enrollments'),
            {'configuration': config.pk,
             'secret': {"meta_business_unit": self.mbu.pk}}
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Enrollment.objects.filter(configuration__name=config.name).count(), 1)
        enrollment = Enrollment.objects.get(configuration__name=config.name)
        self.assertEqual(enrollment.secret.meta_business_unit, self.mbu)

    # update enrollment

    def test_update_enrollment(self):
        enrollment = self.force_enrollment()
        enrollment_secret = enrollment.secret
        self.assertEqual(enrollment.osquery_release, "")
        self.assertEqual(enrollment.secret.quota, None)
        self.assertEqual(enrollment.secret.serial_numbers, None)
        new_osquery_release = get_random_string(12)
        secret_data = EnrollmentSecretSerializer(enrollment_secret).data
        secret_data["id"] = 233333  # to check that there is no enrollment secret creation
        secret_data["quota"] = 23
        secret_data["request_count"] = 2331983  # to check that it cannot be updated
        serial_numbers = [get_random_string(12) for i in range(13)]
        secret_data["serial_numbers"] = serial_numbers
        data = {"configuration": enrollment.configuration.pk,
                "osquery_release": new_osquery_release,
                "secret": secret_data}
        self.set_permissions("osquery.change_enrollment")
        response = self.put_json_data(reverse('osquery_api:enrollment', args=(enrollment.pk,)), data)
        self.assertEqual(response.status_code, 200)
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.osquery_release, new_osquery_release)
        self.assertEqual(enrollment.secret, enrollment_secret)
        self.assertEqual(enrollment.secret.quota, 23)
        self.assertEqual(enrollment.secret.request_count, 0)
        self.assertEqual(enrollment.secret.serial_numbers, serial_numbers)

    # delete enrollment

    def test_delete_enrollment(self):
        enrollment = self.force_enrollment()
        self.set_permissions("osquery.delete_enrollment")
        response = self.delete(reverse('osquery_api:enrollment', args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 204)

    # put pack

    def test_put_pack_unauthorized(self):
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(url, {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_put_pack_permission_denied(self):
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(url, {}, include_token=True)
        self.assertEqual(response.status_code, 403)

    def test_delete_pack_unauthorized(self):
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.delete(url, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_pack_permission_denied(self):
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.delete(url, include_token=True)
        self.assertEqual(response.status_code, 403)

    def test_put_no_queries(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(url, {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': ['This field is required.']}
        )

    def test_put_malformed_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(url, {"queries": {"first_query": {"query": ""}}})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {'first_query': {'interval': ['This field is required.'],
                                         'query': ['This field may not be blank.']}}}
        )

    def test_put_removed_and_snapshot_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select * from users;",
                                         "interval": 10,
                                         "removed": True,
                                         "snapshot": True}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {
                'first_query': {
                    'non_field_errors': [
                        '{"action": "removed"} results are not available in "snapshot" mode']
                }
            }}
        )

    def test_put_diff_query_with_compliance_check(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select 'OK' as ztl_status",
                                         "interval": 10,
                                         "removed": True,
                                         "snapshot": False,
                                         "compliance_check": True}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {
                'first_query': {
                    'non_field_errors': [
                        '{"compliance_check": true} only available in "snapshot" mode']
                }
            }}
        )

    def test_put_query_with_compliance_check_without_ztl_status(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select * from users",
                                         "interval": 10,
                                         "snapshot": True,
                                         "compliance_check": True}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {
                'first_query': {
                    'non_field_errors': [
                        '{"compliance_check": true} only if query contains "ztl_status"']
                }
            }}
        )

    def test_put_invalid_version_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select * from users;",
                                         "interval": 10,
                                         "version": "11201hiuhuih"}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {'first_query': {'version': ['This value does not match the required pattern.']}}}
        )

    def test_put_invalid_platform_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select * from users;",
                                         "interval": 10,
                                         "platform": "rover"}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {'first_query': {'platform': ['Unknown platforms: rover']}}}
        )

    def test_put_invalid_interval_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select * from users;",
                                         "interval": 10920092820982}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {'first_query': {'interval': ['Ensure this value is less than or equal to 604800.']}}}
        )

    def test_put_invalid_shard_query(self):
        self.set_pack_endpoint_put_permissions()
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(
            url,
            {"queries": {"first_query": {"query": "select * from users;",
                                         "interval": 10,
                                         "shard": 110}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'queries': {'first_query': {'shard': ['Ensure this value is less than or equal to 100.']}}}
        )

    def test_put_name_conflict(self):
        self.set_pack_endpoint_put_permissions()
        Pack.objects.create(slug=get_random_string(), name="Yolo")
        url = reverse("osquery_api:pack", args=(get_random_string(),))
        response = self.put_json_data(
            url,
            {"name": "Yolo",
             "queries": {"first_query": {"query": "select 1 from users;",
                                         "interval": 10}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'name': 'A pack with the same name but a different slug already exists'}
        )

    def test_put_pack_json(self):
        self.set_pack_endpoint_put_permissions()
        slug = get_random_string()
        url = reverse("osquery_api:pack", args=(slug,))

        # create pack
        pack = {
            "platform": "posix",
            "version": "1.2.3",
            "discovery": [
              "select 1 from users where username='root'",
            ],
            "queries": {
                "Leverage-A_1": {
                    "query": "select * from launchd where path like '%UserEvent.System.plist';",
                    "interval": "3600",
                    "version": "1.4.9",
                    "description": (
                        "(http://www.intego.com/mac-security-blog/"
                        "new-mac-trojan-discovered-related-to-syria/)"
                    ),
                    "value": "Artifact used by this malware"
                },
                "Leverage-A_2": {
                    "query": "select * from file where path = '/Users/Shared/UserEvent.app';",
                    "interval": "3600",
                    "version": "1.4.5",
                    "description": (
                        "(http://www.intego.com/mac-security-blog/"
                        "new-mac-trojan-discovered-related-to-syria/)"
                    ),
                    "value": "Artifact used by this malware"
                },
                "Snapshot1": {
                    "query": "select 'OK' as ztl_status;",
                    "platform": "darwin",
                    "interval": 7200,
                    "snapshot": True,
                    "denylist": False,
                    "shard": 97,
                    "compliance_check": True
                }
            }
        }
        response = self.put_json_data(url, pack)
        self.assertEqual(response.status_code, 200)
        p = Pack.objects.get(slug=slug)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'created',
             'query_results': {'created': 3, 'deleted': 0, 'present': 0, 'updated': 0}}
        )
        for pack_query in p.packquery_set.select_related("query").all():
            query = pack_query.query
            if pack_query.slug == "Leverage-A_1":
                self.assertEqual(query.platforms, ["posix"])
                self.assertEqual(query.minimum_osquery_version, "1.4.9")
                self.assertIsNone(query.compliance_check)
            elif pack_query.slug == "Leverage-A_2":
                self.assertEqual(query.platforms, ["posix"])
                self.assertEqual(query.minimum_osquery_version, "1.4.5")
                self.assertIsNone(query.compliance_check)
            elif pack_query.slug == "Snapshot1":
                self.assertEqual(query.platforms, ["darwin"])
                self.assertEqual(query.minimum_osquery_version, "1.2.3")
                self.assertEqual(query.compliance_check.name, query.name)
                self.assertEqual(query.compliance_check.version, query.version)
            else:
                raise AssertionError("Unknown plack slug")

        # update pack
        pack["name"] = "YOLO"
        response = self.put_json_data(url, pack)
        self.assertEqual(response.status_code, 200)
        p.refresh_from_db()
        self.assertEqual(p.name, "YOLO")
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'updated',
             'query_results': {'created': 0, 'deleted': 0, 'present': 3, 'updated': 0},
             'updates': {'added': {'name': 'YOLO'}, 'removed': {'name': slug}}}
        )

        # update pack query
        pack_query = p.packquery_set.select_related("query").get(slug="Snapshot1")
        self.assertEqual(pack_query.interval, 7200)
        self.assertEqual(pack_query.query.version, 1)
        pack["queries"]["Snapshot1"]["interval"] = 6789
        response = self.put_json_data(url, pack)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'present',
             'query_results': {'created': 0, 'deleted': 0, 'present': 2, 'updated': 1}}
        )
        pack_query.refresh_from_db()
        self.assertEqual(pack_query.interval, 6789)
        self.assertEqual(pack_query.query.version, 1)
        self.assertEqual(pack_query.query.compliance_check.version, 1)

        # update query
        pack["queries"]["Snapshot1"]["query"] = "select 'FAILED' as ztl_status;"
        response = self.put_json_data(url, pack)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'present',
             'query_results': {'created': 0, 'deleted': 0, 'present': 2, 'updated': 1}}
        )
        pack_query.refresh_from_db()
        self.assertEqual(pack_query.query.sql, "select 'FAILED' as ztl_status;")
        self.assertEqual(pack_query.query.version, 2)
        self.assertEqual(pack_query.query.compliance_check.version, 2)

        # delete pack query
        snapshot_1 = pack["queries"].pop("Snapshot1")
        response = self.put_json_data(url, pack)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'present',
             'query_results': {'created': 0, 'deleted': 1, 'present': 2, 'updated': 0}}
        )
        self.assertEqual(p.packquery_set.filter(slug="Snapshot1").count(), 0)
        query = Query.objects.get(name=f"{slug}{Pack.DELIMITER}Snapshot1")
        with self.assertRaises(PackQuery.DoesNotExist):
            query.packquery

        # re-add pack query with updated query
        snapshot_1["query"] = "select 'OK' as ztl_status"
        pack["queries"]["Snapshot1"] = snapshot_1
        response = self.put_json_data(url, pack)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'present',
             'query_results': {'created': 1, 'deleted': 0, 'present': 2, 'updated': 0}}
        )
        query.refresh_from_db()
        self.assertEqual(query.packquery.slug, "Snapshot1")
        self.assertEqual(query.sql, "select 'OK' as ztl_status")
        self.assertEqual(query.version, 3)
        self.assertEqual(query.compliance_check.version, 3)

    def test_put_pack_osquery_conf(self):
        self.set_pack_endpoint_put_permissions()
        slug = get_random_string()
        url = reverse("osquery_api:pack", args=(slug,))

        pack = """
        {
          // Do not use this query in production!!!
          "platform": "darwin",
          "queries": {
            "WireLurker": {
              "query" : "select * from launchd where \
                name = 'com.apple.periodic-dd-mm-yy.plist';",
              "interval" : "3600",
              "version": "1.4.5",
              "description" : "(https://github.com/PaloAltoNetworks-BD/WireLurkerDetector)",
              "value" : "Artifact used by this malware - 🔥"
              # 🧨
            }
          }
        }
        """

        response = self.put_data(url, pack.encode("utf-8"), "application/x-osquery-conf", include_token=True)
        self.assertEqual(response.status_code, 200)
        p = Pack.objects.get(slug=slug)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'created',
             'query_results': {'created': 1, 'deleted': 0, 'present': 0, 'updated': 0}}
        )
        query = p.packquery_set.first().query
        self.assertEqual(
            query.sql,
            "select * from launchd where                 name = 'com.apple.periodic-dd-mm-yy.plist';"
        )
        self.assertEqual(query.value, "Artifact used by this malware - 🔥")

    def test_put_pack_yaml(self):
        self.set_pack_endpoint_put_permissions()
        slug = get_random_string()
        url = reverse("osquery_api:pack", args=(slug,))

        pack = (
          "---\n"
          "# Do not use this query in production!!!\n\n"
          'platform: "darwin"\n'
          'queries:\n'
          '  WireLurker:\n'
          '    query: >-\n'
          '      select * from launchd where\n'
          "      name = 'com.apple.periodic-dd-mm-yy.plist';\n"
          "    interval: 3600\n"
          "    version: 1.4.5\n"
          "    description: (https://github.com/PaloAltoNetworks-BD/WireLurkerDetector)\n"
          "    value: Artifact used by this malware - 🔥\n"
        )

        response = self.put_data(url, pack.encode("utf-8"), "application/yaml", include_token=True)
        self.assertEqual(response.status_code, 200)
        p = Pack.objects.get(slug=slug)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'created',
             'query_results': {'created': 1, 'deleted': 0, 'present': 0, 'updated': 0}}
        )
        query = p.packquery_set.first().query
        self.assertEqual(
            query.sql,
            "select * from launchd where name = 'com.apple.periodic-dd-mm-yy.plist';"
        )
        self.assertEqual(query.value, "Artifact used by this malware - 🔥")

    def test_delete_pack_404(self):
        self.set_pack_endpoint_delete_permissions()
        slug = get_random_string()
        url = reverse("osquery_api:pack", args=(slug,))
        response = self.delete(url, include_token=True)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {"pack": {"slug": slug}, "result": "absent"}
        )

    def test_delete_pack(self):
        slug = get_random_string()
        url = reverse("osquery_api:pack", args=(slug,))

        # create pack
        pack = {
            "platform": "darwin",
            "discovery": [
              "select 1 from users where username='root'",
            ],
            "queries": {
                "Leverage-A_1": {
                    "query": "select * from launchd where path like '%UserEvent.System.plist';",
                    "interval": "3600",
                    "version": "1.4.5",
                    "description": (
                        "(http://www.intego.com/mac-security-blog/"
                        "new-mac-trojan-discovered-related-to-syria/)"
                    ),
                    "value": "Artifact used by this malware"
                },
                "Leverage-A_2": {
                    "query": "select * from file where path = '/Users/Shared/UserEvent.app';",
                    "interval": "3600",
                    "version": "1.4.5",
                    "description": (
                        "(http://www.intego.com/mac-security-blog/"
                        "new-mac-trojan-discovered-related-to-syria/)"
                    ),
                    "value": "Artifact used by this malware"
                },
                "Snapshot1": {
                    "query": "select * from users;",
                    "platform": "darwin",
                    "interval": 7200,
                    "snapshot": True,
                    "denylist": False,
                    "shard": 97,
                }
            }
        }
        self.set_pack_endpoint_put_permissions()
        self.put_json_data(url, pack)
        p = Pack.objects.get(slug=slug)

        # delete pack
        self.set_pack_endpoint_delete_permissions()
        response = self.delete(url, include_token=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'pack': {'pk': p.pk, 'slug': slug},
             'result': 'deleted',
             'query_results': {'created': 0, 'deleted': 3, 'present': 0, 'updated': 0}}
        )

    # export distributed query results

    def _force_distributed_query(self):
        query = Query.objects.create(
            name=get_random_string(),
            sql="select * from osquery_schedule;"
        )
        return DistributedQuery.objects.create(
            query=query,
            query_version=query.version,
            sql=query.sql,
            valid_from=datetime.utcnow(),
        )

    def test_export_distributed_query_results_401(self):
        dq = self._force_distributed_query()
        response = self.post(reverse("osquery_api:export_distributed_query_results", args=(dq.pk,)),
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_export_distributed_query_results_403(self):
        dq = self._force_distributed_query()
        response = self.post(reverse("osquery_api:export_distributed_query_results", args=(dq.pk,)),
                             include_token=True)
        self.assertEqual(response.status_code, 403)

    def test_export_distributed_query_results_ok(self):
        dq = self._force_distributed_query()
        self.set_permissions("osquery.view_distributedqueryresult")
        response = self.post(reverse("osquery_api:export_distributed_query_results", args=(dq.pk,)),
                             include_token=True)
        self.assertEqual(response.status_code, 201)
