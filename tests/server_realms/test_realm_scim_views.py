from functools import partial, reduce
import json
import operator
from unittest.mock import patch
import uuid
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import APIToken, User
from realms.models import RealmGroup, RealmUser, RealmUserGroupMembership
from realms.scim_views import SCIMPermissions
from .utils import force_realm, force_realm_group, force_realm_user, force_user


class RealmViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # service account
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.com".format(get_random_string(12)),
            is_service_account=True
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.api_token = APIToken.objects.update_or_create_for_user(user=cls.service_account)
        cls.realm = force_realm()
        cls.realm.scim_enabled = True
        cls.realm.save()

    # utility methods

    def serialize_datetime(self, value):
        return f"{value.isoformat(timespec='milliseconds')}Z"

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

    def _make_client_request(self, method, url, data=None, content_type="application/scim+json", include_token=True):
        kwargs = {"HTTP_ACCEPT": 'application/scim+json'}
        if data and method != "get":
            data = json.dumps(data)
            kwargs["content_type"] = content_type
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Bearer {self.api_token}"
        return getattr(self.client, method)(url, data, **kwargs)

    def __getattr__(self, attr):
        if attr in ("get", "patch", "post", "put", "delete"):
            return partial(self._make_client_request, attr)
        raise AttributeError

    # SCIMPermissions

    def test_scim_permissions(self):
        p = SCIMPermissions()
        self.assertEqual(
            p.get_all_perms(),
            ['realms.view_realmuser',
             'realms.add_realmuser',
             'realms.change_realmuser',
             'realms.delete_realmuser',
             'realms.view_realmgroup',
             'realms.add_realmgroup',
             'realms.change_realmgroup',
             'realms.delete_realmgroup']
        )

    # Resource types

    def test_resource_types_unauthorized(self):
        response = self.get(reverse("realms_public:scim_resource_types", args=(self.realm.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {'detail': 'Authentication credentials were not provided.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 401}
        )

    def test_resource_types_permission_denied(self):
        response = self.get(reverse("realms_public:scim_resource_types", args=(self.realm.pk,)))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'detail': 'You do not have permission to perform this action.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 403}
        )

    def test_resource_types_unknown_realm_404(self):
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_resource_types", args=(str(uuid.uuid4()),)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {'detail': 'Unknown Realm.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 404}
        )

    def test_resource_types_no_scim_404(self):
        realm = force_realm()
        self.assertFalse(realm.scim_enabled)
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_resource_types", args=(realm.pk,)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {'detail': 'SCIM not enabled on this Realm.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 404}
        )

    def test_resource_types(self):
        self.set_permissions("realms.change_realmgroup")
        response = self.get(reverse("realms_public:scim_resource_types", args=(self.realm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'description': 'User',
              'endpoint': f'/public/realms/{self.realm.pk}/scim/v2/Users',
              'id': 'User',
              'meta': {'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2'
                                   '/ResourceTypes/urn:ietf:params:scim:schemas:core:2.0:User',
                       'resourceType': 'ResourceType'},
              'name': 'User',
              'schema': 'urn:ietf:params:scim:schemas:core:2.0:User',
              'schemas': ['urn:ietf:params:scim:schemas:core:2.0:ResourceType']},
             {'description': 'Group',
              'endpoint': f'/public/realms/{self.realm.pk}/scim/v2/Groups',
              'id': 'Group',
              'meta': {'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2'
                                   '/ResourceTypes/urn:ietf:params:scim:schemas:core:2.0:Group',
                       'resourceType': 'ResourceType'},
              'name': 'Group',
              'schema': 'urn:ietf:params:scim:schemas:core:2.0:Group',
              'schemas': ['urn:ietf:params:scim:schemas:core:2.0:ResourceType']}]
        )

    # Resource type

    def test_user_resource_type_unauthorized(self):
        response = self.get(reverse("realms_public:scim_resource_type", args=(self.realm.pk, "User")),
                            include_token=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {'detail': 'Authentication credentials were not provided.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 401}
        )

    def test_group_resource_type_permission_denied(self):
        response = self.get(reverse("realms_public:scim_resource_type", args=(self.realm.pk, "Group")))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'detail': 'You do not have permission to perform this action.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 403}
        )

    def test_user_resource_type_unknown_realm_404(self):
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_resource_type", args=(str(uuid.uuid4()), "User")))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {'detail': 'Unknown Realm.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 404}
        )

    def test_group_resource_type_no_scim_404(self):
        realm = force_realm()
        self.assertFalse(realm.scim_enabled)
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_resource_type", args=(realm.pk, "Group")))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {'detail': 'SCIM not enabled on this Realm.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 404}
        )

    def test_user_resource_type(self):
        self.set_permissions("realms.change_realmgroup")
        response = self.get(reverse("realms_public:scim_resource_type", args=(self.realm.pk, "User")))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'description': 'User',
             'endpoint': f'/public/realms/{self.realm.pk}/scim/v2/Users',
             'id': 'User',
             'meta': {'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2'
                                  '/ResourceTypes/urn:ietf:params:scim:schemas:core:2.0:User',
                      'resourceType': 'ResourceType'},
             'name': 'User',
             'schema': 'urn:ietf:params:scim:schemas:core:2.0:User',
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:ResourceType']}
        )

    def test_group_resource_type(self):
        self.set_permissions("realms.change_realmgroup")
        response = self.get(reverse("realms_public:scim_resource_type", args=(self.realm.pk, "Group")))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'description': 'Group',
             'endpoint': f'/public/realms/{self.realm.pk}/scim/v2/Groups',
             'id': 'Group',
             'meta': {'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2'
                                  '/ResourceTypes/urn:ietf:params:scim:schemas:core:2.0:Group',
                      'resourceType': 'ResourceType'},
             'name': 'Group',
             'schema': 'urn:ietf:params:scim:schemas:core:2.0:Group',
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:ResourceType']}
        )

    # Schemas

    def test_schemas_unauthorized(self):
        response = self.get(reverse("realms_public:scim_schemas", args=(self.realm.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {'detail': 'Authentication credentials were not provided.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 401}
        )

    def test_schemas_permission_denied(self):
        response = self.get(reverse("realms_public:scim_schemas", args=(self.realm.pk,)))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'detail': 'You do not have permission to perform this action.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 403}
        )

    def test_schemas_no_scim_404(self):
        realm = force_realm()
        self.assertFalse(realm.scim_enabled)
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_schemas", args=(realm.pk,)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {'detail': 'SCIM not enabled on this Realm.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 404}
        )

    def test_schemas(self):
        self.set_permissions("realms.change_realmgroup")
        response = self.get(reverse("realms_public:scim_schemas", args=(self.realm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {}
        )

    # SP config

    def test_sp_config_unauthorized(self):
        response = self.get(reverse("realms_public:scim_sp_config", args=(self.realm.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {'detail': 'Authentication credentials were not provided.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 401}
        )

    def test_sp_config_permission_denied(self):
        response = self.get(reverse("realms_public:scim_sp_config", args=(self.realm.pk,)))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'detail': 'You do not have permission to perform this action.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 403}
        )

    def test_sp_config_no_scim_404(self):
        realm = force_realm()
        self.assertFalse(realm.scim_enabled)
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_sp_config", args=(realm.pk,)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {'detail': 'SCIM not enabled on this Realm.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 404}
        )

    def test_sp_config_permission(self):
        self.set_permissions("realms.change_realmuser")
        response = self.get(reverse("realms_public:scim_sp_config", args=(self.realm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'authenticationSchemes': [{'description': 'Authentication scheme using the OAuth2 Bearer Token Standard',
                                        'name': 'OAuth Bearer Token',
                                        'type': 'oauthbearertoken'}],
             'bulk': {'maxOperations': 0, 'maxPayloadSize': 0, 'supported': False},
             'changePassword': {'supported': False},
             'etag': {'supported': False},
             'filter': {'maxResults': 500, 'supported': False},
             'meta': {'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/ServiceProviderConfig',
                      'resourceType': 'ServiceProviderConfig'},
             'patch': {'supported': True},
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
             'sort': {'supported': False}}
        )

    # get all users

    def test_users_get_unauthorized(self):
        response = self.get(reverse("realms_public:scim_users", args=(self.realm.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {'detail': 'Authentication credentials were not provided.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 401}
        )

    def test_users_get_permission_denied(self):
        response = self.get(reverse("realms_public:scim_users", args=(self.realm.pk,)))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'detail': 'You do not have permission to perform this action.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 403}
        )

    def test_users_get_no_scim_404(self):
        realm = force_realm()
        self.assertFalse(realm.scim_enabled)
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_users", args=(realm.pk,)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {'detail': 'SCIM not enabled on this Realm.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 404}
        )

    def test_users_get(self):
        force_realm_user()
        _, user = force_realm_user(realm=self.realm, email_count=1)
        email = user.realmemail_set.first()
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_users", args=(self.realm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'Resources': [
                {'active': True,
                 'displayName': f'{user.first_name} {user.last_name}',
                 'emails': [{'primary': True,
                             'type': 'work',
                             'value': email.email}],
                 'externalId': user.scim_external_id,
                 'groups': [],
                 'id': str(user.pk),
                 'meta': {'created': self.serialize_datetime(user.created_at),
                          'last_modified': self.serialize_datetime(user.updated_at),
                          'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Users/{user.pk}',
                          'resourceType': 'User'},
                 'name': {'familyName': user.last_name,
                          'formatted': f'{user.first_name} {user.last_name}',
                          'givenName': user.first_name},
                 'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
                 'userName': user.username}
             ],
             'itemsPerPage': 100,
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
             'startIndex': 1,
             'totalResults': 1}
        )

    # filter users

    def test_users_unsupported_filter(self):
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_users", args=(self.realm.pk,)),
                            {"filter": 'userName eq "yolo" and displayName eq "fomo"'})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'detail': 'This filter is not supported.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'scimType': 'invalidFilter',
             'status': 400}
        )

    def test_users_username_filter(self):
        force_realm_user(realm=self.realm)
        _, user = force_realm_user(realm=self.realm, email_count=1)
        email = user.realmemail_set.first()
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_users", args=(self.realm.pk,)),
                            {"filter": f'userName  eq   "{user.username}"'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'Resources': [
                {'active': True,
                 'displayName': f'{user.first_name} {user.last_name}',
                 'emails': [{'primary': True,
                             'type': 'work',
                             'value': email.email}],
                 'groups': [],
                 'externalId': user.scim_external_id,
                 'id': str(user.pk),
                 'meta': {'created': self.serialize_datetime(user.created_at),
                          'last_modified': self.serialize_datetime(user.updated_at),
                          'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Users/{user.pk}',
                          'resourceType': 'User'},
                 'name': {'familyName': user.last_name,
                          'formatted': f'{user.first_name} {user.last_name}',
                          'givenName': user.first_name},
                 'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
                 'userName': user.username}
             ],
             'itemsPerPage': 100,
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
             'startIndex': 1,
             'totalResults': 1}
        )

    # create user

    def test_create_user_unauthorized(self):
        response = self.post(reverse("realms_public:scim_users", args=(self.realm.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {'detail': 'Authentication credentials were not provided.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 401}
        )

    def test_create_user_permission_denied(self):
        self.set_permissions("realms.view_realmuser")
        response = self.post(reverse("realms_public:scim_users", args=(self.realm.pk,)), {})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'detail': 'You do not have permission to perform this action.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 403}
        )

    def test_create_user_external_id_exists(self):
        _, user = force_realm_user(realm=self.realm)
        self.set_permissions("realms.add_realmuser")
        first_name = get_random_string(12)
        last_name = get_random_string(12)
        username = get_random_string(12)
        email = f"{username}@zentral.com"
        external_id = user.scim_external_id
        response = self.post(
            reverse("realms_public:scim_users", args=(self.realm.pk,)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
             "userName": username,
             "name": {
                 "givenName": first_name,
                 "familyName": last_name,
             },
             "emails": [{
                 "primary": True,
                 "value": email,
                 "type": "work"
             }],
             "displayName": f"{first_name} {last_name}",
             "locale": "en-US",
             "externalId": external_id,
             "password": "1mz050nq",
             "active": True}
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json(),
            {'detail': 'A user with this externalId already exists.',
             'scimType': 'uniqueness',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 409}
        )

    def test_create_user_username_exists(self):
        _, user = force_realm_user(realm=self.realm)
        self.set_permissions("realms.add_realmuser")
        first_name = get_random_string(12)
        last_name = get_random_string(12)
        username = user.username
        email = f"{username}@zentral.com"
        external_id = get_random_string(12)
        response = self.post(
            reverse("realms_public:scim_users", args=(self.realm.pk,)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
             "userName": username,
             "name": {
                 "givenName": first_name,
                 "familyName": last_name,
             },
             "emails": [{
                 "primary": True,
                 "value": email,
                 "type": "work"
             }],
             "displayName": f"{first_name} {last_name}",
             "locale": "en-US",
             "externalId": external_id,
             "password": "1mz050nq",
             "active": True}
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json(),
            {'detail': 'A user with this userName already exists.',
             'scimType': 'uniqueness',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 409}
        )

    def test_create_user_invalid_input(self):
        self.set_permissions("realms.add_realmuser")
        response = self.post(
            reverse("realms_public:scim_users", args=(self.realm.pk,)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
             "userName": get_random_string(12),
             "emails": [{
                 "primary": True,
                 "type": "work"
             }],
             "locale": "en-US",
             "password": "1mz050nq",
             "active": True}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'detail': 'Invalid input.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 400,
             'scimType': 'invalidSyntax'}
        )

    def test_create_user(self):
        self.set_permissions("realms.add_realmuser")
        first_name = get_random_string(12)
        last_name = get_random_string(12)
        username = get_random_string(12)
        email = f"{username}@zentral.com"
        external_id = get_random_string(12)
        response = self.post(
            reverse("realms_public:scim_users", args=(self.realm.pk,)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
             "userName": username,
             "name": {
                 "givenName": first_name,
                 "familyName": last_name,
             },
             "emails": [{
                 "primary": True,
                 "value": email,
                 "type": "work"
             }],
             "displayName": f"{first_name} {last_name}",
             "locale": "en-US",
             "externalId": external_id,
             "password": "1mz050nq",
             "active": True}
        )
        self.assertEqual(response.status_code, 201)
        user = RealmUser.objects.get(realm=self.realm, username=username)
        email_qs = user.realmemail_set.all()
        self.assertEqual(email_qs.count(), 1)
        email = email_qs.first()
        self.assertEqual(
            response.json(),
            {'active': True,
             'displayName': f'{user.first_name} {user.last_name}',
             'emails': [{'primary': True,
                         'type': 'work',
                         'value': email.email}],
             'groups': [],
             'externalId': user.scim_external_id,
             'id': str(user.pk),
             'meta': {'created': self.serialize_datetime(user.created_at),
                      'last_modified': self.serialize_datetime(user.updated_at),
                      'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Users/{user.pk}',
                      'resourceType': 'User'},
             'name': {'familyName': user.last_name,
                      'formatted': f'{user.first_name} {user.last_name}',
                      'givenName': user.first_name},
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
             'userName': user.username}
        )
        self.assertEqual(user.email, email.email)

    def test_create_user_no_display_name(self):
        self.set_permissions("realms.add_realmuser")
        first_name = get_random_string(12)
        last_name = get_random_string(12)
        username = get_random_string(12)
        email = f"{username}@zentral.com"
        external_id = get_random_string(12)
        response = self.post(
            reverse("realms_public:scim_users", args=(self.realm.pk,)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
             "userName": username,
             "name": {
                 "givenName": first_name,
                 "familyName": last_name,
             },
             "emails": [{
                 "primary": True,
                 "value": email,
                 "type": "work"
             }],
             "locale": "en-US",
             "externalId": external_id,
             "password": "1mz050nq",
             "active": True}
        )
        self.assertEqual(response.status_code, 201)
        user = RealmUser.objects.get(realm=self.realm, username=username)
        email_qs = user.realmemail_set.all()
        self.assertEqual(email_qs.count(), 1)
        email = email_qs.first()
        self.assertEqual(
            response.json(),
            {'active': True,
             'displayName': f'{user.first_name} {user.last_name}',
             'emails': [{'primary': True,
                         'type': 'work',
                         'value': email.email}],
             'groups': [],
             'externalId': user.scim_external_id,
             'id': str(user.pk),
             'meta': {'created': self.serialize_datetime(user.created_at),
                      'last_modified': self.serialize_datetime(user.updated_at),
                      'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Users/{user.pk}',
                      'resourceType': 'User'},
             'name': {'familyName': user.last_name,
                      'formatted': f'{user.first_name} {user.last_name}',
                      'givenName': user.first_name},
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
             'userName': user.username}
        )
        self.assertEqual(user.email, email.email)

    def test_create_user_no_update_user(self):
        self.set_permissions("realms.add_realmuser")
        first_name = get_random_string(12)
        last_name = get_random_string(12)
        username = get_random_string(12)
        email = f"{username}@zentral.com"
        external_id = get_random_string(12)
        user_to_update = force_user(username=username, email=email, active=False)
        user_to_update_first_name = user_to_update.first_name
        user_to_update_last_name = user_to_update.last_name
        self.assertFalse(user_to_update.is_active)
        self.assertFalse(self.realm.enabled_for_login)  # no updates
        response = self.post(
            reverse("realms_public:scim_users", args=(self.realm.pk,)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
             "userName": username,
             "name": {
                 "givenName": first_name,
                 "familyName": last_name,
             },
             "emails": [{
                 "primary": True,
                 "value": email,
                 "type": "work"
             }],
             "locale": "en-US",
             "externalId": external_id,
             "password": "1mz050nq",
             "active": True}
        )
        self.assertEqual(response.status_code, 201)
        user_to_update.refresh_from_db()
        self.assertEqual(user_to_update.first_name, user_to_update_first_name)
        self.assertEqual(user_to_update.last_name, user_to_update_last_name)
        self.assertFalse(user_to_update.is_active)

    def test_create_user_update_user(self):
        self.set_permissions("realms.add_realmuser")
        first_name = get_random_string(12)
        last_name = get_random_string(12)
        username = get_random_string(12)
        email = f"{username}@zentral.com"
        external_id = get_random_string(12)
        user_to_update = force_user(username=username, active=False)
        self.assertFalse(user_to_update.is_active)
        unmanaged_user = force_user()
        unmanaged_user_first_name = unmanaged_user.first_name
        unmanaged_user_last_name = unmanaged_user.last_name
        self.realm.enabled_for_login = True  # update
        self.realm.save()
        response = self.post(
            reverse("realms_public:scim_users", args=(self.realm.pk,)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
             "userName": username,
             "name": {
                 "givenName": first_name,
                 "familyName": last_name,
             },
             "emails": [{
                 "primary": True,
                 "value": email,
                 "type": "work"
             }],
             "locale": "en-US",
             "externalId": external_id,
             "password": "1mz050nq",
             "active": True}
        )
        self.assertEqual(response.status_code, 201)
        user_to_update.refresh_from_db()
        self.assertEqual(user_to_update.username, username)
        self.assertEqual(user_to_update.email, email)
        self.assertEqual(user_to_update.first_name, first_name)
        self.assertEqual(user_to_update.last_name, last_name)
        self.assertTrue(user_to_update.is_active)
        unmanaged_user.refresh_from_db()
        self.assertEqual(unmanaged_user.first_name, unmanaged_user_first_name)
        self.assertEqual(unmanaged_user.last_name, unmanaged_user_last_name)

    # update user put

    def test_update_user_put_unauthorized(self):
        _, user = force_realm_user(realm=self.realm)
        response = self.put(reverse("realms_public:scim_user", args=(self.realm.pk, user.pk)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {'detail': 'Authentication credentials were not provided.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 401}
        )

    def test_update_user_put_permission_denied(self):
        _, user = force_realm_user(realm=self.realm)
        self.set_permissions("realms.view_realmuser")
        response = self.put(reverse("realms_public:scim_user", args=(self.realm.pk, user.pk)), {})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'detail': 'You do not have permission to perform this action.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 403}
        )

    def test_update_user_put(self):
        _, user = force_realm_user(realm=self.realm)
        first_name = get_random_string(12)
        last_name = get_random_string(12)
        username = get_random_string(12)
        email = f"{username}@zentral.com"
        external_id = get_random_string(12)
        self.set_permissions("realms.change_realmuser")
        response = self.put(
            reverse("realms_public:scim_user", args=(self.realm.pk, user.pk)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
             "userName": username,
             "name": {
                 "givenName": first_name,
                 "familyName": last_name,
             },
             "emails": [{
                 "primary": True,
                 "value": email,
                 "type": "work"
             }],
             "displayName": f"{first_name} {last_name}",
             "locale": "en-US",
             "externalId": external_id,
             "password": "1mz050nq",
             "active": False}
        )
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertEqual(
            response.json(),
            {'active': False,
             'displayName': f'{first_name} {last_name}',
             'emails': [{'primary': True,
                         'type': 'work',
                         'value': email}],
             'groups': [],
             'externalId': external_id,
             'id': str(user.pk),
             'meta': {'created': self.serialize_datetime(user.created_at),
                      'last_modified': self.serialize_datetime(user.updated_at),
                      'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Users/{user.pk}',
                      'resourceType': 'User'},
             'name': {'familyName': last_name,
                      'formatted': f'{user.first_name} {user.last_name}',
                      'givenName': first_name},
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
             'userName': username}
        )
        self.assertEqual(user.email, email)

    def test_update_user_update_user(self):
        _, realm_user = force_realm_user(realm=self.realm)
        first_name = get_random_string(12)
        last_name = get_random_string(12)
        username = get_random_string(12)
        email = f"{username}@zentral.com"
        external_id = get_random_string(12)
        user_to_update = force_user(username=realm_user.username, active=True)
        self.assertTrue(user_to_update.is_active)
        unmanaged_user = force_user()
        unmanaged_user_first_name = unmanaged_user.first_name
        unmanaged_user_last_name = unmanaged_user.last_name
        self.realm.enabled_for_login = True  # update
        self.realm.save()
        self.set_permissions("realms.change_realmuser")
        response = self.put(
            reverse("realms_public:scim_user", args=(self.realm.pk, realm_user.pk)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
             "userName": username,
             "name": {
                 "givenName": first_name,
                 "familyName": last_name,
             },
             "emails": [{
                 "primary": True,
                 "value": email,
                 "type": "work"
             }],
             "displayName": f"{first_name} {last_name}",
             "locale": "en-US",
             "externalId": external_id,
             "password": "1mz050nq",
             "active": False}
        )
        self.assertEqual(response.status_code, 200)
        user_to_update.refresh_from_db()
        self.assertEqual(user_to_update.username, username)
        self.assertEqual(user_to_update.email, email)
        self.assertEqual(user_to_update.first_name, first_name)
        self.assertEqual(user_to_update.last_name, last_name)
        self.assertFalse(user_to_update.is_active)
        unmanaged_user.refresh_from_db()
        self.assertEqual(unmanaged_user.first_name, unmanaged_user_first_name)
        self.assertEqual(unmanaged_user.last_name, unmanaged_user_last_name)

    def test_update_user_put_no_external_id(self):
        _, user = force_realm_user(realm=self.realm)
        external_id = user.scim_external_id
        self.assertIsNotNone(external_id)
        first_name = get_random_string(12)
        last_name = get_random_string(12)
        username = get_random_string(12)
        email = f"{username}@zentral.com"
        self.set_permissions("realms.change_realmuser")
        response = self.put(
            reverse("realms_public:scim_user", args=(self.realm.pk, user.pk)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
             "userName": username,
             "name": {
                 "givenName": first_name,
                 "familyName": last_name,
             },
             "emails": [{
                 "primary": True,
                 "value": email,
                 "type": "work"
             }],
             "displayName": f"{first_name} {last_name}",
             "locale": "en-US",
             "password": "1mz050nq",
             "active": False}
        )
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertEqual(
            response.json(),
            {'active': False,
             'displayName': f'{first_name} {last_name}',
             'emails': [{'primary': True,
                         'type': 'work',
                         'value': email}],
             'groups': [],
             'externalId': external_id,
             'id': str(user.pk),
             'meta': {'created': self.serialize_datetime(user.created_at),
                      'last_modified': self.serialize_datetime(user.updated_at),
                      'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Users/{user.pk}',
                      'resourceType': 'User'},
             'name': {'familyName': last_name,
                      'formatted': f'{user.first_name} {user.last_name}',
                      'givenName': first_name},
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
             'userName': username}
        )
        self.assertEqual(user.email, email)

    def test_update_user_put_external_id_null(self):
        _, user = force_realm_user(realm=self.realm)
        external_id = user.scim_external_id
        self.assertIsNotNone(external_id)
        first_name = get_random_string(12)
        last_name = get_random_string(12)
        username = get_random_string(12)
        email = f"{username}@zentral.com"
        self.set_permissions("realms.change_realmuser")
        response = self.put(
            reverse("realms_public:scim_user", args=(self.realm.pk, user.pk)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
             "userName": username,
             "name": {
                 "givenName": first_name,
                 "familyName": last_name,
             },
             "emails": [{
                 "primary": True,
                 "value": email,
                 "type": "work"
             }],
             "displayName": f"{first_name} {last_name}",
             "locale": "en-US",
             "password": "1mz050nq",
             "externalId": None,
             "active": False}
        )
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertEqual(
            response.json(),
            {'active': False,
             'displayName': f'{first_name} {last_name}',
             'emails': [{'primary': True,
                         'type': 'work',
                         'value': email}],
             'groups': [],
             'externalId': external_id,
             'id': str(user.pk),
             'meta': {'created': self.serialize_datetime(user.created_at),
                      'last_modified': self.serialize_datetime(user.updated_at),
                      'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Users/{user.pk}',
                      'resourceType': 'User'},
             'name': {'familyName': last_name,
                      'formatted': f'{user.first_name} {user.last_name}',
                      'givenName': first_name},
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
             'userName': username}
        )
        self.assertEqual(user.email, email)

    # get user by pk

    def test_user_get_unauthorized(self):
        _, user = force_realm_user(realm=self.realm)
        response = self.get(reverse("realms_public:scim_user", args=(self.realm.pk, user.pk)), include_token=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {'detail': 'Authentication credentials were not provided.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 401}
        )

    def test_user_get_permission_denied(self):
        _, user = force_realm_user(realm=self.realm)
        response = self.get(reverse("realms_public:scim_user", args=(self.realm.pk, user.pk)))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'detail': 'You do not have permission to perform this action.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 403}
        )

    def test_user_get_no_scim_404(self):
        realm, user = force_realm_user()
        self.assertFalse(realm.scim_enabled)
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_user", args=(realm.pk, user.pk)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {'detail': 'SCIM not enabled on this Realm.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 404}
        )

    def test_user_get_not_found_404(self):
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_user", args=(self.realm.pk, str(uuid.uuid4()))))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {'detail': 'User not found.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 404}
        )

    def test_user_get(self):
        _, user = force_realm_user(realm=self.realm, email_count=1)
        email = user.realmemail_set.first()
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_user", args=(self.realm.pk, user.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'active': True,
             'displayName': f'{user.first_name} {user.last_name}',
             'emails': [{'primary': True,
                         'type': 'work',
                         'value': email.email}],
             'groups': [],
             'externalId': user.scim_external_id,
             'id': str(user.pk),
             'meta': {'created': self.serialize_datetime(user.created_at),
                      'last_modified': self.serialize_datetime(user.updated_at),
                      'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Users/{user.pk}',
                      'resourceType': 'User'},
             'name': {'familyName': user.last_name,
                      'formatted': f'{user.first_name} {user.last_name}',
                      'givenName': user.first_name},
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
             'userName': user.username}
        )

    def test_user_get_nested_groups(self):
        root_group = force_realm_group(realm=self.realm)
        group = force_realm_group(realm=self.realm, parent=root_group)
        _, user = force_realm_user(realm=self.realm, group=group)
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_user", args=(self.realm.pk, user.pk)))
        self.assertEqual(response.status_code, 200)
        response_json = response.json()
        response_json["groups"].sort(key=lambda d: d["value"])
        expected_response = {
            'active': True,
            'displayName': f'{user.first_name} {user.last_name}',
            'emails': [],
            'groups': [
                {"value": str(root_group.pk),
                 "type": "indirect",
                 "$ref": f"https://zentral/public/realms/{self.realm.pk}/scim/v2/Groups/{root_group.pk}",
                 "display": root_group.display_name},
                {"value": str(group.pk),
                 "type": "direct",
                 "$ref": f"https://zentral/public/realms/{self.realm.pk}/scim/v2/Groups/{group.pk}",
                 "display": group.display_name}
            ],
            'externalId': user.scim_external_id,
            'id': str(user.pk),
            'meta': {'created': self.serialize_datetime(user.created_at),
                     'last_modified': self.serialize_datetime(user.updated_at),
                     'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Users/{user.pk}',
                     'resourceType': 'User'},
            'name': {'familyName': user.last_name,
                     'formatted': f'{user.first_name} {user.last_name}',
                     'givenName': user.first_name},
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': user.username
        }
        expected_response["groups"].sort(key=lambda d: d["value"])
        self.assertEqual(response_json, expected_response)

    # get all groups

    def test_groups_get_unauthorized(self):
        response = self.get(reverse("realms_public:scim_groups", args=(self.realm.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {'detail': 'Authentication credentials were not provided.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 401}
        )

    def test_groups_get_permission_denied(self):
        self.set_permissions("realms.view_realmuser")
        response = self.get(reverse("realms_public:scim_groups", args=(self.realm.pk,)))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'detail': 'You do not have permission to perform this action.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 403}
        )

    def test_groups_get_no_scim_404(self):
        realm = force_realm()
        self.assertFalse(realm.scim_enabled)
        self.set_permissions("realms.view_realmgroup")
        response = self.get(reverse("realms_public:scim_groups", args=(realm.pk,)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {'detail': 'SCIM not enabled on this Realm.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 404}
        )

    def test_groups_get(self):
        force_realm_group()
        group = force_realm_group(realm=self.realm)
        self.set_permissions("realms.view_realmgroup")
        response = self.get(reverse("realms_public:scim_groups", args=(self.realm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'Resources': [
                {'displayName': group.display_name,
                 'members': [],
                 'externalId': group.scim_external_id,
                 'id': str(group.pk),
                 'meta': {'created': self.serialize_datetime(group.created_at),
                          'last_modified': self.serialize_datetime(group.updated_at),
                          'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Groups/{group.pk}',
                          'resourceType': 'Group'},
                 'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
             ],
             'itemsPerPage': 100,
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
             'startIndex': 1,
             'totalResults': 1}
        )

    # filter groups

    def test_groups_unsupported_filter(self):
        self.set_permissions("realms.view_realmgroup")
        response = self.get(reverse("realms_public:scim_groups", args=(self.realm.pk,)),
                            {"filter": 'displayName co "yolo"'})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'detail': 'This filter is not supported.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'scimType': 'invalidFilter',
             'status': 400}
        )

    def test_groups_displayname_filter(self):
        force_realm_group(realm=self.realm)
        group = force_realm_group(realm=self.realm)
        self.set_permissions("realms.view_realmgroup")
        response = self.get(reverse("realms_public:scim_groups", args=(self.realm.pk,)),
                            {"filter": f'displayName eq "{group.display_name}"'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'Resources': [
                {'displayName': group.display_name,
                 'members': [],
                 'externalId': group.scim_external_id,
                 'id': str(group.pk),
                 'meta': {'created': self.serialize_datetime(group.created_at),
                          'last_modified': self.serialize_datetime(group.updated_at),
                          'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Groups/{group.pk}',
                          'resourceType': 'Group'},
                 'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
             ],
             'itemsPerPage': 100,
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
             'startIndex': 1,
             'totalResults': 1}
        )

    # create group

    def test_create_group_unauthorized(self):
        response = self.post(reverse("realms_public:scim_groups", args=(self.realm.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {'detail': 'Authentication credentials were not provided.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 401}
        )

    def test_create_group_permission_denied(self):
        self.set_permissions("realms.add_realmuser")
        response = self.post(reverse("realms_public:scim_groups", args=(self.realm.pk,)), {})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'detail': 'You do not have permission to perform this action.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 403}
        )

    def test_create_group_external_id_exists(self):
        group = force_realm_group(realm=self.realm)
        self.set_permissions("realms.add_realmgroup")
        display_name = get_random_string(12)
        external_id = group.scim_external_id
        response = self.post(
            reverse("realms_public:scim_groups", args=(self.realm.pk,)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
             "displayName": display_name,
             "externalId": external_id},
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json(),
            {'detail': 'A group with this externalId already exists.',
             'scimType': 'uniqueness',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 409}
        )

    def test_create_group_display_name_exists(self):
        group = force_realm_group(realm=self.realm)
        self.set_permissions("realms.add_realmgroup")
        display_name = group.display_name
        external_id = get_random_string(12)
        response = self.post(
            reverse("realms_public:scim_groups", args=(self.realm.pk,)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
             "displayName": display_name,
             "externalId": external_id}
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json(),
            {'detail': 'A group with this displayName already exists.',
             'scimType': 'uniqueness',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 409}
        )

    @patch("zentral.contrib.mdm.inventory.update_realm_tags")
    def test_create_group(self, update_realm_tags):
        self.set_permissions("realms.add_realmgroup")
        display_name = get_random_string(12)
        external_id = get_random_string(12)
        response = self.post(
            reverse("realms_public:scim_groups", args=(self.realm.pk,)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
             "displayName": display_name,
             "externalId": external_id}
        )
        self.assertEqual(response.status_code, 201)
        group = RealmGroup.objects.get(realm=self.realm, display_name=display_name)
        self.assertEqual(
            response.json(),
            {'displayName': display_name,
             'members': [],
             'externalId': group.scim_external_id,
             'id': str(group.pk),
             'meta': {'created': self.serialize_datetime(group.created_at),
                      'last_modified': self.serialize_datetime(group.updated_at),
                      'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Groups/{group.pk}',
                      'resourceType': 'Group'},
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
        )
        update_realm_tags.assert_not_called()

    @patch("zentral.contrib.mdm.inventory.update_realm_tags")
    def test_create_group_with_members(self, update_realm_tags):
        _, user = force_realm_user(realm=self.realm)
        group = force_realm_group(realm=self.realm)
        display_name = get_random_string(12)
        external_id = get_random_string(12)
        self.set_permissions("realms.add_realmgroup")
        response = self.post(
            reverse("realms_public:scim_groups", args=(self.realm.pk,)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
             "displayName": display_name,
             "externalId": external_id,
             "members": [{"value": str(user.pk)}, {"value": str(group.pk)}]}
        )
        self.assertEqual(response.status_code, 201)
        created_group = RealmGroup.objects.get(realm=self.realm, display_name=display_name)
        self.assertEqual(
            response.json(),
            {'displayName': display_name,
             'members': [
                 {"value": str(group.pk),
                  "$ref": f"https://zentral/public/realms/{self.realm.pk}/scim/v2/Groups/{group.pk}",
                  "type": "Group"},
                 {"value": str(user.pk),
                  "$ref": f"https://zentral/public/realms/{self.realm.pk}/scim/v2/Users/{user.pk}",
                  "type": "User"},
             ],
             'externalId': external_id,
             'id': str(created_group.pk),
             'meta': {'created': self.serialize_datetime(created_group.created_at),
                      'last_modified': self.serialize_datetime(created_group.updated_at),
                      'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Groups/{created_group.pk}',
                      'resourceType': 'Group'},
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
        )
        update_realm_tags.assert_called_once_with(self.realm)

    # update group put

    def test_update_group_put_unauthorized(self):
        group = force_realm_group(realm=self.realm)
        response = self.put(reverse("realms_public:scim_group", args=(self.realm.pk, group.pk)),
                            {}, include_token=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {'detail': 'Authentication credentials were not provided.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 401}
        )

    def test_update_group_put_permission_denied(self):
        group = force_realm_group(realm=self.realm)
        self.set_permissions("realms.change_realmuser")
        response = self.put(reverse("realms_public:scim_group", args=(self.realm.pk, group.pk)), {})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'detail': 'You do not have permission to perform this action.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 403}
        )

    @patch("zentral.contrib.mdm.inventory.update_realm_tags")
    def test_update_group_put(self, update_realm_tags):
        group = force_realm_group(realm=self.realm)
        display_name = get_random_string(12)
        self.set_permissions("realms.change_realmgroup")
        response = self.put(
            reverse("realms_public:scim_group", args=(self.realm.pk, group.pk)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
             "displayName": display_name,
             "externalId": group.scim_external_id,
             "members": []}
        )
        self.assertEqual(response.status_code, 200)
        group.refresh_from_db()
        self.assertEqual(
            response.json(),
            {'displayName': display_name,
             'members': [],
             'externalId': group.scim_external_id,
             'id': str(group.pk),
             'meta': {'created': self.serialize_datetime(group.created_at),
                      'last_modified': self.serialize_datetime(group.updated_at),
                      'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Groups/{group.pk}',
                      'resourceType': 'Group'},
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
        )
        update_realm_tags.assert_not_called()

    def test_update_group_put_no_external_id(self):
        group = force_realm_group(realm=self.realm)
        external_id = group.scim_external_id
        self.assertIsNotNone(external_id)
        display_name = get_random_string(12)
        self.set_permissions("realms.change_realmgroup")
        response = self.put(
            reverse("realms_public:scim_group", args=(self.realm.pk, group.pk)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
             "displayName": display_name,
             "members": []}
        )
        self.assertEqual(response.status_code, 200)
        group.refresh_from_db()
        self.assertEqual(
            response.json(),
            {'displayName': display_name,
             'members': [],
             'externalId': external_id,
             'id': str(group.pk),
             'meta': {'created': self.serialize_datetime(group.created_at),
                      'last_modified': self.serialize_datetime(group.updated_at),
                      'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Groups/{group.pk}',
                      'resourceType': 'Group'},
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
        )

    def test_update_group_put_external_id_null(self):
        group = force_realm_group(realm=self.realm)
        external_id = group.scim_external_id
        self.assertIsNotNone(external_id)
        display_name = get_random_string(12)
        self.set_permissions("realms.change_realmgroup")
        response = self.put(
            reverse("realms_public:scim_group", args=(self.realm.pk, group.pk)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
             "displayName": display_name,
             "externalId": None,
             "members": []}
        )
        self.assertEqual(response.status_code, 200)
        group.refresh_from_db()
        self.assertEqual(
            response.json(),
            {'displayName': display_name,
             'members': [],
             'externalId': external_id,
             'id': str(group.pk),
             'meta': {'created': self.serialize_datetime(group.created_at),
                      'last_modified': self.serialize_datetime(group.updated_at),
                      'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Groups/{group.pk}',
                      'resourceType': 'Group'},
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
        )

    def test_update_group_invalid_input(self):
        group = force_realm_group(realm=self.realm)
        self.set_permissions("realms.change_realmgroup")
        response = self.put(
            reverse("realms_public:scim_group", args=(self.realm.pk, group.pk)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
             "members": []}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'detail': 'Invalid input.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 400,
             'scimType': 'invalidSyntax'}
        )

    @patch("zentral.contrib.mdm.inventory.update_realm_tags")
    def test_update_group_put_with_members(self, update_realm_tags):
        group = force_realm_group(realm=self.realm)
        old_group_member = force_realm_group(realm=self.realm, parent=group)
        _, old_user_member = force_realm_user(realm=self.realm, group=group)
        new_group_member = force_realm_group(realm=self.realm)
        _, new_user_member = force_realm_user(realm=self.realm)
        self.assertEqual(RealmUserGroupMembership.objects.filter(group=group, user=old_user_member).count(), 1)
        self.assertEqual(old_group_member.parent, group)
        display_name = get_random_string(12)
        self.set_permissions("realms.change_realmgroup")
        response = self.put(
            reverse("realms_public:scim_group", args=(self.realm.pk, group.pk)),
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
             "displayName": display_name,
             "externalId": group.scim_external_id,
             "members": [{"value": str(new_group_member.pk)},
                         {"value": str(new_user_member.pk)}]}
        )
        self.assertEqual(response.status_code, 200)
        group.refresh_from_db()
        self.assertEqual(
            response.json(),
            {'displayName': display_name,
             'members': [
                 {"value": str(new_group_member.pk),
                  "$ref": f"https://zentral/public/realms/{self.realm.pk}/scim/v2/Groups/{new_group_member.pk}",
                  "type": "Group"},
                 {"value": str(new_user_member.pk),
                  "$ref": f"https://zentral/public/realms/{self.realm.pk}/scim/v2/Users/{new_user_member.pk}",
                  "type": "User"},
             ],
             'externalId': group.scim_external_id,
             'id': str(group.pk),
             'meta': {'created': self.serialize_datetime(group.created_at),
                      'last_modified': self.serialize_datetime(group.updated_at),
                      'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Groups/{group.pk}',
                      'resourceType': 'Group'},
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
        )
        self.assertEqual(RealmUserGroupMembership.objects.filter(group=group, user=old_user_member).count(), 0)
        old_group_member.refresh_from_db()
        self.assertIsNone(old_group_member.parent)
        update_realm_tags.assert_called_once_with(self.realm)

    # get group by pk

    def test_group_get_unauthorized(self):
        group = force_realm_group(realm=self.realm)
        response = self.get(reverse("realms_public:scim_group", args=(self.realm.pk, group.pk)), include_token=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {'detail': 'Authentication credentials were not provided.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 401}
        )

    def test_group_get_permission_denied(self):
        group = force_realm_group(realm=self.realm)
        response = self.get(reverse("realms_public:scim_group", args=(self.realm.pk, group.pk)))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'detail': 'You do not have permission to perform this action.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 403}
        )

    def test_group_get_no_scim_404(self):
        group = force_realm_group()
        realm = group.realm
        self.assertFalse(realm.scim_enabled)
        self.set_permissions("realms.view_realmgroup")
        response = self.get(reverse("realms_public:scim_group", args=(realm.pk, group.pk)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {'detail': 'SCIM not enabled on this Realm.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 404}
        )

    def test_group_get_not_found_404(self):
        self.set_permissions("realms.view_realmgroup")
        response = self.get(reverse("realms_public:scim_group", args=(self.realm.pk, str(uuid.uuid4()))))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {'detail': 'Group not found.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 404}
        )

    def test_group_get(self):
        group = force_realm_group(realm=self.realm)
        self.set_permissions("realms.view_realmgroup")
        response = self.get(reverse("realms_public:scim_group", args=(self.realm.pk, group.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'displayName': group.display_name,
             'members': [],
             'externalId': group.scim_external_id,
             'id': str(group.pk),
             'meta': {'created': self.serialize_datetime(group.created_at),
                      'last_modified': self.serialize_datetime(group.updated_at),
                      'location': f'https://zentral/public/realms/{self.realm.pk}/scim/v2/Groups/{group.pk}',
                      'resourceType': 'Group'},
             'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']}
        )

    # delete group

    def test_group_delete_unauthorized(self):
        group = force_realm_group(realm=self.realm)
        response = self.delete(reverse("realms_public:scim_group", args=(self.realm.pk, group.pk)),
                               include_token=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {'detail': 'Authentication credentials were not provided.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 401}
        )

    def test_group_delete_permission_denied(self):
        group = force_realm_group(realm=self.realm)
        self.set_permissions("realms.view_realmgroup")
        response = self.delete(reverse("realms_public:scim_group", args=(self.realm.pk, group.pk)))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'detail': 'You do not have permission to perform this action.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 403}
        )

    def test_group_delete_no_scim_404(self):
        group = force_realm_group()
        realm = group.realm
        self.assertFalse(realm.scim_enabled)
        self.set_permissions("realms.delete_realmgroup")
        response = self.delete(reverse("realms_public:scim_group", args=(realm.pk, group.pk)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {'detail': 'SCIM not enabled on this Realm.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 404}
        )

    def test_group_delete_not_found_404(self):
        self.set_permissions("realms.delete_realmgroup")
        response = self.delete(reverse("realms_public:scim_group", args=(self.realm.pk, str(uuid.uuid4()))))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json(),
            {'detail': 'Group not found.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 404}
        )

    @patch("zentral.contrib.mdm.inventory.update_realm_tags")
    def test_group_delete(self, update_realm_tags):
        group = force_realm_group(realm=self.realm)
        self.set_permissions("realms.delete_realmgroup")
        response = self.delete(reverse("realms_public:scim_group", args=(self.realm.pk, group.pk)))
        self.assertEqual(response.status_code, 204)
        update_realm_tags.assert_called_once_with(self.realm)
