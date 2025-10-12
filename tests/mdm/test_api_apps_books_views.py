from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit
from .utils import force_dep_enrollment_session, force_location, force_location_asset


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

    def _make_request(self, method, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["content_type"] = "application/json"
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return method(url, **kwargs)

    def delete(self, *args, **kwargs):
        return self._make_request(self.client.delete, *args, **kwargs)

    def get(self, *args, **kwargs):
        return self._make_request(self.client.get, *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._make_request(self.client.post, *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._make_request(self.client.put, *args, **kwargs)

    # locations

    def test_locations_unauthorized(self):
        response = self.get(reverse("mdm_api:locations"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_locations_permission_denied(self):
        response = self.get(reverse("mdm_api:locations"))
        self.assertEqual(response.status_code, 403)

    def test_locations_method_not_allowed(self):
        self.set_permissions("mdm.add_location")
        response = self.post(reverse("mdm_api:locations"), {})
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json(), {'detail': 'Method "POST" not allowed.'})

    def test_locations(self):
        self.set_permissions("mdm.view_location")
        location = force_location()
        location.refresh_from_db()  # server_token_expiration_date format!!!
        response = self.get(reverse("mdm_api:locations"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'country_code': 'DE',
              'created_at': location.created_at.isoformat(),
              'id': location.pk,
              'library_uid': str(location.library_uid),
              'mdm_info_id': str(location.mdm_info_id),
              'name': location.name,
              'organization_name': location.organization_name,
              'platform': 'enterprisestore',
              'server_token_expiration_date': location.server_token_expiration_date.isoformat(),
              'updated_at': location.updated_at.isoformat(),
              'website_url': 'https://business.apple.com'}]
        )

    def test_location_by_mdm_info_id(self):
        self.set_permissions("mdm.view_location")
        location = force_location()
        location.refresh_from_db()  # server_token_expiration_date format!!!
        response = self.get(reverse("mdm_api:locations") + f"?mdm_info_id={location.mdm_info_id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'country_code': 'DE',
              'created_at': location.created_at.isoformat(),
              'id': location.pk,
              'library_uid': str(location.library_uid),
              'mdm_info_id': str(location.mdm_info_id),
              'name': location.name,
              'organization_name': location.organization_name,
              'platform': 'enterprisestore',
              'server_token_expiration_date': location.server_token_expiration_date.isoformat(),
              'updated_at': location.updated_at.isoformat(),
              'website_url': 'https://business.apple.com'}]
        )

    def test_location_by_mdm_info_id_no_results(self):
        self.set_permissions("mdm.view_location")
        response = self.get(reverse("mdm_api:locations") + "?mdm_info_id=734898e6-dbcf-4bba-ab60-5ede4633a033")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_location_by_name(self):
        self.set_permissions("mdm.view_location")
        location = force_location()
        location.refresh_from_db()  # server_token_expiration_date format!!!
        response = self.get(reverse("mdm_api:locations") + f"?name={location.name}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'country_code': 'DE',
              'created_at': location.created_at.isoformat(),
              'id': location.pk,
              'library_uid': str(location.library_uid),
              'mdm_info_id': str(location.mdm_info_id),
              'name': location.name,
              'organization_name': location.organization_name,
              'platform': 'enterprisestore',
              'server_token_expiration_date': location.server_token_expiration_date.isoformat(),
              'updated_at': location.updated_at.isoformat(),
              'website_url': 'https://business.apple.com'}]
        )

    def test_location_by_name_no_results(self):
        self.set_permissions("mdm.view_location")
        response = self.get(reverse("mdm_api:locations") + "?name=yolo")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_location_by_organization_name(self):
        self.set_permissions("mdm.view_location")
        location = force_location()
        location.refresh_from_db()  # server_token_expiration_date format!!!
        response = self.get(reverse("mdm_api:locations") + f"?organization_name={location.organization_name}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'country_code': 'DE',
              'created_at': location.created_at.isoformat(),
              'id': location.pk,
              'library_uid': str(location.library_uid),
              'mdm_info_id': str(location.mdm_info_id),
              'name': location.name,
              'organization_name': location.organization_name,
              'platform': 'enterprisestore',
              'server_token_expiration_date': location.server_token_expiration_date.isoformat(),
              'updated_at': location.updated_at.isoformat(),
              'website_url': 'https://business.apple.com'}]
        )

    def test_location_by_organization_name_no_results(self):
        self.set_permissions("mdm.view_location")
        response = self.get(reverse("mdm_api:locations") + "?organization_name=yolo")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    # location

    def test_location_unauthorized(self):
        location = force_location()
        response = self.get(reverse("mdm_api:location", args=(location.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_location_permission_denied(self):
        location = force_location()
        response = self.get(reverse("mdm_api:location", args=(location.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_location_method_not_allowed(self):
        location = force_location()
        self.set_permissions("mdm.change_location")
        response = self.put(reverse("mdm_api:location", args=(location.pk,)), {})
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json(), {'detail': 'Method "PUT" not allowed.'})

    def test_location(self):
        location = force_location()
        self.set_permissions("mdm.view_location")
        location = force_location()
        location.refresh_from_db()  # server_token_expiration_date format!!!
        response = self.get(reverse("mdm_api:location", args=(location.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'country_code': 'DE',
             'created_at': location.created_at.isoformat(),
             'id': location.pk,
             'library_uid': str(location.library_uid),
             'mdm_info_id': str(location.mdm_info_id),
             'name': location.name,
             'organization_name': location.organization_name,
             'platform': 'enterprisestore',
             'server_token_expiration_date': location.server_token_expiration_date.isoformat(),
             'updated_at': location.updated_at.isoformat(),
             'website_url': 'https://business.apple.com'}
        )

    # location assets

    def test_location_assets_unauthorized(self):
        response = self.get(reverse("mdm_api:location_assets"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_location_assets_permission_denied(self):
        response = self.get(reverse("mdm_api:location_assets"))
        self.assertEqual(response.status_code, 403)

    def test_location_assets_method_not_allowed(self):
        self.set_permissions("mdm.add_locationasset")
        response = self.post(reverse("mdm_api:location_assets"), {})
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json(), {'detail': 'Method "POST" not allowed.'})

    def test_location_assets(self):
        self.set_permissions("mdm.view_locationasset")
        la = force_location_asset()
        response = self.get(reverse("mdm_api:location_assets"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'asset': la.asset.pk,
              'assigned_count': 0,
              'available_count': 0,
              'created_at': la.created_at.isoformat(),
              'id': la.pk,
              'location': la.location.pk,
              'retired_count': 0,
              'total_count': 0,
              'updated_at': la.updated_at.isoformat()}]
        )

    def test_location_assets_by_adam_id(self):
        self.set_permissions("mdm.view_locationasset")
        la = force_location_asset()
        response = self.get(reverse("mdm_api:location_assets") + f"?adam_id={la.asset.adam_id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'asset': la.asset.pk,
              'assigned_count': 0,
              'available_count': 0,
              'created_at': la.created_at.isoformat(),
              'id': la.pk,
              'location': la.location.pk,
              'retired_count': 0,
              'total_count': 0,
              'updated_at': la.updated_at.isoformat()}]
        )

    def test_location_assets_by_adam_id_no_results(self):
        self.set_permissions("mdm.view_locationasset")
        force_location_asset()
        response = self.get(reverse("mdm_api:location_assets") + "?adam_id=yolo")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_location_assets_by_pricing_param(self):
        self.set_permissions("mdm.view_locationasset")
        la = force_location_asset()
        response = self.get(reverse("mdm_api:location_assets") + f"?pricing_param={la.asset.pricing_param}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'asset': la.asset.pk,
              'assigned_count': 0,
              'available_count': 0,
              'created_at': la.created_at.isoformat(),
              'id': la.pk,
              'location': la.location.pk,
              'retired_count': 0,
              'total_count': 0,
              'updated_at': la.updated_at.isoformat()}]
        )

    def test_location_assets_by_pricing_param_no_results(self):
        self.set_permissions("mdm.view_locationasset")
        force_location_asset()
        response = self.get(reverse("mdm_api:location_assets") + "?pricing_param=yolo")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_location_assets_by_location_id(self):
        self.set_permissions("mdm.view_locationasset")
        la = force_location_asset()
        force_location_asset()
        response = self.get(reverse("mdm_api:location_assets") + f"?location_id={la.location.pk}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'asset': la.asset.pk,
              'assigned_count': 0,
              'available_count': 0,
              'created_at': la.created_at.isoformat(),
              'id': la.pk,
              'location': la.location.pk,
              'retired_count': 0,
              'total_count': 0,
              'updated_at': la.updated_at.isoformat()}]
        )

    def test_location_assets_by_location_id_no_results(self):
        self.set_permissions("mdm.view_locationasset")
        force_location_asset()
        location = force_location()
        response = self.get(reverse("mdm_api:location_assets") + f"?location_id={location.pk}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_location_assets_all_filters(self):
        self.set_permissions("mdm.view_locationasset")
        la = force_location_asset()
        response = self.get(
            reverse("mdm_api:location_assets")
            + f"?adam_id={la.asset.adam_id}"
            + f"&pricing_param={la.asset.pricing_param}"
            + f"&location_id={la.location.pk}"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'asset': la.asset.pk,
              'assigned_count': 0,
              'available_count': 0,
              'created_at': la.created_at.isoformat(),
              'id': la.pk,
              'location': la.location.pk,
              'retired_count': 0,
              'total_count': 0,
              'updated_at': la.updated_at.isoformat()}]
        )
