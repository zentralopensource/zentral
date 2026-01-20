from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.cert_issuer_backends import CertIssuerBackend
from zentral.contrib.mdm.models import SCEPIssuer
from zentral.core.events.base import AuditEvent
from .utils import force_dep_enrollment, force_scep_issuer


class MDMSCEPIssuerAPIViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
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

    # list SCEP issuers

    def test_list_scep_issuers_unauthorized(self):
        response = self.get(reverse("mdm_api:scep_issuers"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_scep_issuers_permission_denied(self):
        response = self.get(reverse("mdm_api:scep_issuers"))
        self.assertEqual(response.status_code, 403)

    def test_list_scep_issuers(self):
        self.set_permissions("mdm.view_scepissuer")
        scep_issuer = force_scep_issuer()
        response = self.get(reverse("mdm_api:scep_issuers"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'backend': 'STATIC_CHALLENGE',
              'created_at': scep_issuer.created_at.isoformat(),
              'id': str(scep_issuer.pk),
              'key_usage': 0,
              'key_size': 2048,
              'name': scep_issuer.name,
              'description': '',
              'provisioning_uid': None,
              'static_challenge_kwargs': {'challenge': scep_issuer.get_static_challenge_kwargs()['challenge']},
              'updated_at': scep_issuer.updated_at.isoformat(),
              'url': scep_issuer.url,
              'version': 1}]
        )

    def test_list_scep_issuers_name_filter(self):
        scep_issuer = force_scep_issuer(backend=CertIssuerBackend.IDent)
        force_scep_issuer()
        self.set_permissions("mdm.view_scepissuer")
        response = self.get(reverse("mdm_api:scep_issuers"), data={"name": scep_issuer.name})
        self.assertEqual(response.status_code, 200)
        backend_kwargs = scep_issuer.get_ident_kwargs()
        self.assertEqual(
            response.json(),
            [{'backend': 'IDENT',
              'created_at': scep_issuer.created_at.isoformat(),
              'id': str(scep_issuer.pk),
              'key_usage': 0,
              'key_size': 2048,
              'name': scep_issuer.name,
              'description': '',
              'provisioning_uid': None,
              'ident_kwargs': {
                  'url': backend_kwargs['url'],
                  'bearer_token': backend_kwargs['bearer_token'],
                  'request_timeout': backend_kwargs['request_timeout'],
                  'max_retries': backend_kwargs['max_retries'],
              },
              'updated_at': scep_issuer.updated_at.isoformat(),
              'url': scep_issuer.url,
              'version': 1}]
        )

    # get SCEP issuer

    def test_get_scep_issuer_unauthorized(self):
        scep_issuer = force_scep_issuer()
        response = self.get(reverse("mdm_api:scep_issuer", args=(scep_issuer.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_scep_issuer_permission_denied(self):
        scep_issuer = force_scep_issuer()
        response = self.get(reverse("mdm_api:scep_issuer", args=(scep_issuer.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_scep_issuer(self):
        scep_issuer = force_scep_issuer()
        self.set_permissions("mdm.view_scepissuer")
        response = self.get(reverse("mdm_api:scep_issuer", args=(scep_issuer.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'backend': 'STATIC_CHALLENGE',
             'created_at': scep_issuer.created_at.isoformat(),
             'id': str(scep_issuer.pk),
             'key_usage': 0,
             'key_size': 2048,
             'name': scep_issuer.name,
             'description': '',
             'provisioning_uid': None,
             'static_challenge_kwargs': {'challenge': scep_issuer.get_static_challenge_kwargs()['challenge']},
             'updated_at': scep_issuer.updated_at.isoformat(),
             'url': scep_issuer.url,
             'version': 1}
        )

    def test_get_provisioned_scep_issuer(self):
        scep_issuer = force_scep_issuer(provisioning_uid="YoLoFoMo")
        self.set_permissions("mdm.view_scepissuer")
        response = self.get(reverse("mdm_api:scep_issuer", args=(scep_issuer.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            # no backend related attributes
            {'created_at': scep_issuer.created_at.isoformat(),
             'description': '',
             'id': str(scep_issuer.pk),
             'key_size': 2048,
             'key_usage': 0,
             'name': scep_issuer.name,
             'provisioning_uid': "YoLoFoMo",
             'updated_at': scep_issuer.updated_at.isoformat(),
             'url': scep_issuer.url,
             'version': 1}
        )

    # create scep_issuer

    def test_create_scep_issuer_unauthorized(self):
        response = self.post(reverse("mdm_api:scep_issuers"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_scep_issuer_permission_denied(self):
        response = self.post(reverse("mdm_api:scep_issuers"), {})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_scep_issuer(self, post_event):
        self.set_permissions("mdm.add_scepissuer")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:scep_issuers"),
                {'backend': 'OKTA_CA',
                 'key_usage': 5,
                 'key_size': 4096,
                 'name': name,
                 'description': 'description',
                 'okta_ca_kwargs': {
                     'url': 'https://example.com/ndes/',
                     'username': 'yolo',
                     'password': 'fomo',
                 },
                 'url': 'https://example.com/scep/'}
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        scep_issuer = SCEPIssuer.objects.get(name=name)
        self.assertEqual(
            data,
            {'backend': 'OKTA_CA',
             'created_at': scep_issuer.created_at.isoformat(),
             'description': 'description',
             'id': str(scep_issuer.pk),
             'key_size': 4096,
             'key_usage': 5,
             'okta_ca_kwargs': {'password': 'fomo',
                                'url': 'https://example.com/ndes/',
                                'username': 'yolo'},
             'name': name,
             'provisioning_uid': None,
             'updated_at': scep_issuer.updated_at.isoformat(),
             'url': 'https://example.com/scep/',
             'version': 1}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'created',
             'object': {
                 'model': 'mdm.scepissuer',
                 'new_value': {
                     'backend': 'OKTA_CA',
                     'backend_kwargs': {'password_hash': (
                                            '48ffcddb8b19a5f98d4b1b8c08b4024b12b6f24affeb50b1265aed528a2dd671'
                                        ),
                                        'url': 'https://example.com/ndes/',
                                        'username': 'yolo'},
                     'created_at': scep_issuer.created_at,
                     'description': 'description',
                     'key_size': 4096,
                     'key_usage': 5,
                     'name': scep_issuer.name,
                     'pk': str(scep_issuer.pk),
                     'updated_at': scep_issuer.updated_at,
                     'url': scep_issuer.url,
                     'version': 1
                 },
                 'pk': str(scep_issuer.pk)}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_scep_issuer": [str(scep_issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_scep_issuer_errors(self, post_event):
        self.set_permissions("mdm.add_scepissuer")
        response = self.post(
            reverse("mdm_api:scep_issuers"),
            {'backend': 'DIGICERT',
             'key_usage': 5,
             'key_size': 4096,
             'name': get_random_string(12),
             'description': 'description',
             'digicert_kwargs': {
                 'api_base_url': 'https://www.example.com',
                 'profile_guid': 'not a valid guid',
             },
             'url': 'https://example.com/scep/'}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'digicert_kwargs': {'api_base_url': ["URL path must end with '/api/'"],
                                 'api_token': ['This field is required.'],
                                 'business_unit_guid': ['This field is required.'],
                                 'default_seat_email': ['This field is required.'],
                                 'profile_guid': ['Not a valid GUID']}},
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_scep_issuer_digicert_min(self, post_event):
        self.set_permissions("mdm.add_scepissuer")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:scep_issuers"),
                {'backend': 'DIGICERT',
                 'key_usage': 5,
                 'key_size': 4096,
                 'name': name,
                 'description': 'description',
                 'digicert_kwargs': {
                     'api_token': 'haha',
                     'profile_guid': '60a3ce98-b05f-4f1b-83b0-200d82723134',
                     'business_unit_guid': '34f0d9a5-4603-4d07-baf3-2071f6e5b874',
                     'default_seat_email': 'yolo@example.com',
                 },
                 'url': 'https://example.com/scep/'}
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        scep_issuer = SCEPIssuer.objects.get(name=name)
        self.assertEqual(
            data,
            {'backend': 'DIGICERT',
             'created_at': scep_issuer.created_at.isoformat(),
             'description': 'description',
             'id': str(scep_issuer.pk),
             'key_size': 4096,
             'key_usage': 5,
             'digicert_kwargs': {
                 'api_base_url': 'https://one.digicert.com/mpki/api/',
                 'api_token': 'haha',
                 'profile_guid': '60a3ce98-b05f-4f1b-83b0-200d82723134',
                 'business_unit_guid': '34f0d9a5-4603-4d07-baf3-2071f6e5b874',
                 'seat_type': 'DEVICE_SEAT',
                 'seat_id_mapping': 'common_name',
                 'default_seat_email': 'yolo@example.com',
             },
             'name': name,
             'provisioning_uid': None,
             'updated_at': scep_issuer.updated_at.isoformat(),
             'url': 'https://example.com/scep/',
             'version': 1}
        )
        backend = scep_issuer.get_backend(load=True)
        self.assertEqual(backend.api_base_url, 'https://one.digicert.com/mpki/api/')
        self.assertEqual(backend.api_token, 'haha')
        self.assertEqual(backend.profile_guid, '60a3ce98-b05f-4f1b-83b0-200d82723134'),
        self.assertEqual(backend.business_unit_guid, '34f0d9a5-4603-4d07-baf3-2071f6e5b874'),
        self.assertEqual(backend.seat_type, 'DEVICE_SEAT'),
        self.assertEqual(backend.seat_id_mapping, 'common_name'),
        self.assertEqual(backend.default_seat_email, 'yolo@example.com')
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'created',
             'object': {
                 'model': 'mdm.scepissuer',
                 'new_value': {
                     'backend': 'DIGICERT',
                     'backend_kwargs': {
                         'api_base_url': 'https://one.digicert.com/mpki/api/',
                         'api_token_hash': '090b235e9eb8f197f2dd927937222c570396d971222d9009a9189e2b6cc0a2c1',
                         'profile_guid': '60a3ce98-b05f-4f1b-83b0-200d82723134',
                         'business_unit_guid': '34f0d9a5-4603-4d07-baf3-2071f6e5b874',
                         'seat_type': 'DEVICE_SEAT',
                         'seat_id_mapping': 'common_name',
                         'default_seat_email': 'yolo@example.com',
                     },
                     'created_at': scep_issuer.created_at,
                     'description': 'description',
                     'key_size': 4096,
                     'key_usage': 5,
                     'name': scep_issuer.name,
                     'pk': str(scep_issuer.pk),
                     'updated_at': scep_issuer.updated_at,
                     'url': scep_issuer.url,
                     'version': 1
                 },
                 'pk': str(scep_issuer.pk)}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_scep_issuer": [str(scep_issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_scep_issuer_ident(self, post_event):
        self.set_permissions("mdm.add_scepissuer")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:scep_issuers"),
                {'backend': 'IDENT',
                 'key_usage': 5,
                 'key_size': 4096,
                 'name': name,
                 'description': 'description',
                 'ident_kwargs': {
                     'bearer_token': 'YoloFomo',
                     'max_retries': 5,
                     'request_timeout': 123,
                     'url': 'https://example.com/ident/',
                 },
                 'url': 'https://example.com/scep/'}
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        scep_issuer = SCEPIssuer.objects.get(name=name)
        self.assertEqual(
            data,
            {'backend': 'IDENT',
             'created_at': scep_issuer.created_at.isoformat(),
             'description': 'description',
             'id': str(scep_issuer.pk),
             'key_size': 4096,
             'key_usage': 5,
             'ident_kwargs': {
                 'bearer_token': 'YoloFomo',
                 'max_retries': 5,
                 'request_timeout': 123,
                 'url': 'https://example.com/ident/',
             },
             'name': name,
             'provisioning_uid': None,
             'updated_at': scep_issuer.updated_at.isoformat(),
             'url': 'https://example.com/scep/',
             'version': 1}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'created',
             'object': {
                 'model': 'mdm.scepissuer',
                 'new_value': {
                     'backend': 'IDENT',
                     'backend_kwargs': {
                         'bearer_token_hash': '69fd1658dc95ce930f492232866e1c980ac3fb4e4319a8189b141be3d18a6a33',
                         'max_retries': 5,
                         'request_timeout': 123,
                         'url': 'https://example.com/ident/',
                     },
                     'created_at': scep_issuer.created_at,
                     'description': 'description',
                     'key_size': 4096,
                     'key_usage': 5,
                     'name': scep_issuer.name,
                     'pk': str(scep_issuer.pk),
                     'updated_at': scep_issuer.updated_at,
                     'url': scep_issuer.url,
                     'version': 1
                 },
                 'pk': str(scep_issuer.pk)}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_scep_issuer": [str(scep_issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # update scep_issuer

    def test_update_scep_issuer_unauthorized(self):
        scep_issuer = force_scep_issuer()
        response = self.put(reverse("mdm_api:scep_issuer", args=(scep_issuer.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_scep_issuer_permission_denied(self):
        scep_issuer = force_scep_issuer()
        response = self.put(reverse("mdm_api:scep_issuer", args=(scep_issuer.pk,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_scep_issuer_cannot_be_updated(self):
        scep_issuer = force_scep_issuer(provisioning_uid=get_random_string(12))
        self.set_permissions("mdm.change_scepissuer")
        response = self.put(
            reverse("mdm_api:scep_issuer", args=(scep_issuer.pk,)),
            {'backend': 'MICROSOFT_CA',
             'key_usage': 5,
             'key_size': 4096,
             'name': get_random_string(12),
             'description': 'description',
             'microsoft_ca_kwargs': {
                 'url': 'https://example.com/ndes/',
                 'username': 'yolo',
                 'password': 'fomo',
             },
             'url': scep_issuer.url}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['This SCEP issuer cannot be updated.'])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_scep_issuer(self, post_event):
        scep_issuer = force_scep_issuer()
        prev_value = scep_issuer.serialize_for_event()
        new_name = get_random_string(12)
        self.set_permissions("mdm.change_scepissuer")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(
                reverse("mdm_api:scep_issuer", args=(scep_issuer.pk,)),
                {'backend': 'MICROSOFT_CA',
                 'key_usage': 5,
                 'key_size': 4096,
                 'name': new_name,
                 'description': 'description',
                 'microsoft_ca_kwargs': {
                     'url': 'https://example.com/ndes/',
                     'username': 'yolo',
                     'password': 'fomo',
                 },
                 'url': scep_issuer.url}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        scep_issuer.refresh_from_db()
        self.assertEqual(
            data,
            {'backend': 'MICROSOFT_CA',
             'created_at': scep_issuer.created_at.isoformat(),
             'description': 'description',
             'id': str(scep_issuer.pk),
             'key_size': 4096,
             'key_usage': 5,
             'microsoft_ca_kwargs': {'password': 'fomo',
                                     'url': 'https://example.com/ndes/',
                                     'username': 'yolo'},
             'name': scep_issuer.name,
             'provisioning_uid': None,
             'updated_at': scep_issuer.updated_at.isoformat(),
             'url': scep_issuer.url,
             'version': 2}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'updated',
             'object': {
                 'model': 'mdm.scepissuer',
                 'new_value': {
                     'backend': 'MICROSOFT_CA',
                     'backend_kwargs': {'password_hash': (
                                            '48ffcddb8b19a5f98d4b1b8c08b4024b12b6f24affeb50b1265aed528a2dd671'
                                        ),
                                        'url': 'https://example.com/ndes/',
                                        'username': 'yolo'},
                     'created_at': scep_issuer.created_at,
                     'description': 'description',
                     'key_size': 4096,
                     'key_usage': 5,
                     'name': scep_issuer.name,
                     'pk': str(scep_issuer.pk),
                     'updated_at': scep_issuer.updated_at,
                     'url': scep_issuer.url,
                     'version': 2
                 },
                 'pk': str(scep_issuer.pk),
                 'prev_value': prev_value}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_scep_issuer": [str(scep_issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # delete scep_issuer

    def test_delete_scep_issuer_unauthorized(self):
        scep_issuer = force_scep_issuer()
        response = self.delete(reverse("mdm_api:scep_issuer", args=(scep_issuer.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_scep_issuer_permission_denied(self):
        scep_issuer = force_scep_issuer()
        response = self.delete(reverse("mdm_api:scep_issuer", args=(scep_issuer.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_scep_issuer_cannot_be_deleted(self):
        dep_enrollment = force_dep_enrollment(self.mbu)
        self.set_permissions("mdm.delete_scepissuer")
        response = self.delete(reverse("mdm_api:scep_issuer", args=(dep_enrollment.scep_issuer.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['This SCEP issuer cannot be deleted.'])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_scep_issuer(self, post_event):
        scep_issuer = force_scep_issuer()
        prev_value = scep_issuer.serialize_for_event()
        self.set_permissions("mdm.delete_scepissuer")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:scep_issuer", args=(scep_issuer.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.scepissuer",
                 "pk": str(scep_issuer.pk),
                 "prev_value": prev_value,
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_scep_issuer": [str(scep_issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
