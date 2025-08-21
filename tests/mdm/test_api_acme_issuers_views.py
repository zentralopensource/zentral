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
from zentral.contrib.mdm.models import ACMEIssuer
from zentral.core.events.base import AuditEvent
from .utils import force_dep_enrollment, force_acme_issuer


class MDMACMEIssuerAPIViewsTestCase(TestCase):
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
        cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)

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

    # list ACME issuers

    def test_list_acme_issuers_unauthorized(self):
        response = self.get(reverse("mdm_api:acme_issuers"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_acme_issuers_permission_denied(self):
        response = self.get(reverse("mdm_api:acme_issuers"))
        self.assertEqual(response.status_code, 403)

    def test_list_acme_issuers(self):
        self.set_permissions("mdm.view_acmeissuer")
        acme_issuer = force_acme_issuer()
        response = self.get(reverse("mdm_api:acme_issuers"))
        self.assertEqual(response.status_code, 200)
        backend_kwargs = acme_issuer.get_microsoft_ca_kwargs()
        self.assertEqual(
            response.json(),
            [{'attest': True,
              'backend': 'MICROSOFT_CA',
              'created_at': acme_issuer.created_at.isoformat(),
              'description': '',
              'directory_url': acme_issuer.directory_url,
              'extended_key_usage': [],
              'hardware_bound': True,
              'id': str(acme_issuer.pk),
              'key_size': 384,
              'key_type': 'ECSECPrimeRandom',
              'name': acme_issuer.name,
              'microsoft_ca_kwargs': {
                  'url': backend_kwargs['url'],
                  'username': backend_kwargs['username'],
                  'password': backend_kwargs['password'],
              },
              'provisioning_uid': None,
              'updated_at': acme_issuer.updated_at.isoformat(),
              'usage_flags': 1,
              'version': 1}]
        )

    def test_list_acme_issuers_name_filter(self):
        acme_issuer = force_acme_issuer(backend=CertIssuerBackend.IDent)
        force_acme_issuer()
        self.set_permissions("mdm.view_acmeissuer")
        response = self.get(reverse("mdm_api:acme_issuers"), data={"name": acme_issuer.name})
        self.assertEqual(response.status_code, 200)
        backend_kwargs = acme_issuer.get_ident_kwargs()
        self.assertEqual(
            response.json(),
            [{'attest': True,
              'backend': 'IDENT',
              'created_at': acme_issuer.created_at.isoformat(),
              'description': '',
              'directory_url': acme_issuer.directory_url,
              'extended_key_usage': [],
              'hardware_bound': True,
              'id': str(acme_issuer.pk),
              'key_size': 384,
              'key_type': 'ECSECPrimeRandom',
              'ident_kwargs': {
                  'url': backend_kwargs['url'],
                  'bearer_token': backend_kwargs['bearer_token'],
                  'request_timeout': backend_kwargs['request_timeout'],
                  'max_retries': backend_kwargs['max_retries'],
              },
              'name': acme_issuer.name,
              'provisioning_uid': None,
              'updated_at': acme_issuer.updated_at.isoformat(),
              'usage_flags': 1,
              'version': 1}]
        )

    # get ACME issuer

    def test_get_acme_issuer_unauthorized(self):
        acme_issuer = force_acme_issuer()
        response = self.get(reverse("mdm_api:acme_issuer", args=(acme_issuer.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_acme_issuer_permission_denied(self):
        acme_issuer = force_acme_issuer()
        response = self.get(reverse("mdm_api:acme_issuer", args=(acme_issuer.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_acme_issuer(self):
        acme_issuer = force_acme_issuer()
        self.set_permissions("mdm.view_acmeissuer")
        response = self.get(reverse("mdm_api:acme_issuer", args=(acme_issuer.pk,)))
        self.assertEqual(response.status_code, 200)
        backend_kwargs = acme_issuer.get_microsoft_ca_kwargs()
        self.assertEqual(
            response.json(),
            {'attest': True,
             'backend': 'MICROSOFT_CA',
             'created_at': acme_issuer.created_at.isoformat(),
             'description': '',
             'directory_url': acme_issuer.directory_url,
             'extended_key_usage': [],
             'hardware_bound': True,
             'id': str(acme_issuer.pk),
             'key_size': 384,
             'key_type': 'ECSECPrimeRandom',
             'usage_flags': 1,
             'microsoft_ca_kwargs': {
                 'url': backend_kwargs['url'],
                 'username': backend_kwargs['username'],
                 'password': backend_kwargs['password'],
             },
             'name': acme_issuer.name,
             'provisioning_uid': None,
             'updated_at': acme_issuer.updated_at.isoformat(),
             'version': 1}
        )

    def test_get_provisioned_acme_issuer(self):
        acme_issuer = force_acme_issuer(provisioning_uid="YoLoFoMo")
        self.set_permissions("mdm.view_acmeissuer")
        response = self.get(reverse("mdm_api:acme_issuer", args=(acme_issuer.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            # no backend related attributes
            {'attest': True,
             'created_at': acme_issuer.created_at.isoformat(),
             'description': '',
             'directory_url': acme_issuer.directory_url,
             'extended_key_usage': [],
             'hardware_bound': True,
             'id': str(acme_issuer.pk),
             'key_size': 384,
             'key_type': 'ECSECPrimeRandom',
             'usage_flags': 1,
             'name': acme_issuer.name,
             'provisioning_uid': acme_issuer.provisioning_uid,
             'updated_at': acme_issuer.updated_at.isoformat(),
             'version': 1}
        )

    # create acme_issuer

    def test_create_acme_issuer_unauthorized(self):
        response = self.post(reverse("mdm_api:acme_issuers"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_acme_issuer_permission_denied(self):
        response = self.post(reverse("mdm_api:acme_issuers"), {})
        self.assertEqual(response.status_code, 403)

    def test_create_acme_issuer_hardware_bound_rsa(self):
        self.set_permissions("mdm.add_acmeissuer")
        response = self.post(
            reverse("mdm_api:acme_issuers"),
            {'attest': True,
             'backend': 'STATIC_CHALLENGE',
             'description': 'description',
             'directory_url': 'https://example.com/acme/',
             'hardware_bound': True,
             'key_size': 2048,
             'key_type': 'RSA',  # no OK for hardware bound
             'name': get_random_string(12),
             'static_challenge_kwargs': {'challenge': 'yolo'},
             'usage_flags': 5}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'key_type': ['Hardware bound keys must be of type ECSECPrimeRandom']}
        )

    def test_create_acme_issuer_rsa_too_small(self):
        self.set_permissions("mdm.add_acmeissuer")
        response = self.post(
            reverse("mdm_api:acme_issuers"),
            {'attest': False,
             'backend': 'STATIC_CHALLENGE',
             'description': 'description',
             'directory_url': 'https://example.com/acme/',
             'hardware_bound': False,
             'key_size': 512,  # too small
             'key_type': 'RSA',
             'name': get_random_string(12),
             'static_challenge_kwargs': {'challenge': 'yolo'},
             'usage_flags': 5}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'key_size': ['RSA Key size must be a multiple of 8 in the range of 1024 through 4096']}
        )

    def test_create_acme_issuer_rsa_too_big(self):
        self.set_permissions("mdm.add_acmeissuer")
        response = self.post(
            reverse("mdm_api:acme_issuers"),
            {'attest': False,
             'backend': 'STATIC_CHALLENGE',
             'description': 'description',
             'directory_url': 'https://example.com/acme/',
             'hardware_bound': False,
             'key_size': 8192,  # too big
             'key_type': 'RSA',
             'name': get_random_string(12),
             'static_challenge_kwargs': {'challenge': 'yolo'},
             'usage_flags': 5}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'key_size': ['RSA Key size must be a multiple of 8 in the range of 1024 through 4096']}
        )

    def test_create_acme_issuer_rsa_not_a_multiple_of_8(self):
        self.set_permissions("mdm.add_acmeissuer")
        response = self.post(
            reverse("mdm_api:acme_issuers"),
            {'attest': False,
             'backend': 'STATIC_CHALLENGE',
             'description': 'description',
             'directory_url': 'https://example.com/acme/',
             'hardware_bound': False,
             'key_size': 3003,  # not a multiple of 8
             'key_type': 'RSA',
             'name': get_random_string(12),
             'static_challenge_kwargs': {'challenge': 'yolo'},
             'usage_flags': 5}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'key_size': ['RSA Key size must be a multiple of 8 in the range of 1024 through 4096']}
        )

    def test_create_acme_issuer_ec_not_a_good_size(self):
        self.set_permissions("mdm.add_acmeissuer")
        response = self.post(
            reverse("mdm_api:acme_issuers"),
            {'attest': False,
             'backend': 'STATIC_CHALLENGE',
             'description': 'description',
             'directory_url': 'https://example.com/acme/',
             'hardware_bound': False,
             'key_size': 512,  # not a valid value
             'key_type': 'ECSECPrimeRandom',
             'name': get_random_string(12),
             'static_challenge_kwargs': {'challenge': 'yolo'},
             'usage_flags': 5}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'key_size': ['ECSECPrimeRandom keys must be one of the P-192, P-256, P-384, or P-521 curves']}
        )

    def test_create_acme_issuer_hardware_bound_ec_not_a_good_size(self):
        self.set_permissions("mdm.add_acmeissuer")
        response = self.post(
            reverse("mdm_api:acme_issuers"),
            {'attest': False,
             'backend': 'STATIC_CHALLENGE',
             'description': 'description',
             'directory_url': 'https://example.com/acme/',
             'hardware_bound': True,
             'key_size': 521,  # not a valid value
             'key_type': 'ECSECPrimeRandom',
             'name': get_random_string(12),
             'static_challenge_kwargs': {'challenge': 'yolo'},
             'usage_flags': 5}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'key_size': ['Hardware bound ECSECPrimeRandom keys must be one of the P-256 or P-384 curves']}
        )

    def test_create_acme_issuer_attest_without_hardware_bound(self):
        self.set_permissions("mdm.add_acmeissuer")
        response = self.post(
            reverse("mdm_api:acme_issuers"),
            {'attest': True,
             'backend': 'STATIC_CHALLENGE',
             'description': 'description',
             'directory_url': 'https://example.com/acme/',
             'hardware_bound': False,  # required for attest
             'key_size': 384,
             'key_type': 'ECSECPrimeRandom',
             'name': get_random_string(12),
             'static_challenge_kwargs': {'challenge': 'yolo'},
             'usage_flags': 5}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'hardware_bound': ['When attest is true, hardware_bound also needs to be true']}
        )

    def test_create_acme_issuer_wrong_backend_kwargs(self):
        self.set_permissions("mdm.add_acmeissuer")
        response = self.post(
            reverse("mdm_api:acme_issuers"),
            {'attest': True,
             'backend': 'STATIC_CHALLENGE',
             'description': 'description',
             'directory_url': 'https://example.com/acme/',
             'hardware_bound': False,  # required for attest
             'key_size': 384,
             'key_type': 'ECSECPrimeRandom',
             'name': get_random_string(12),
             'static_challenge_kwargs': {'challenge': 'yolo'},
             'microsoft_ca_kwargs': {
                 'url': 'https://example.com/ndes',
                 'username': 'yolo',
                 'password': 'fomo',
             },
             'usage_flags': 5}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'microsoft_ca_kwargs': ['This field cannot be set for this backend.']}
        )

    def test_create_acme_issuer_missing_backend_kwargs(self):
        self.set_permissions("mdm.add_acmeissuer")
        response = self.post(
            reverse("mdm_api:acme_issuers"),
            {'attest': True,
             'backend': 'IDENT',
             'description': 'description',
             'directory_url': 'https://example.com/acme/',
             'hardware_bound': True,
             'key_size': 256,
             'key_type': 'ECSECPrimeRandom',
             'name': get_random_string(12),
             'ident_kwargs': {},  # Missing kwargs
             'usage_flags': 5}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'ident_kwargs': {'bearer_token': ['This field is required.'],
                              'url': ['This field is required.']}}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_acme_issuer(self, post_event):
        self.set_permissions("mdm.add_acmeissuer")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:acme_issuers"),
                {'attest': True,
                 'backend': 'OKTA_CA',
                 'description': 'description',
                 'directory_url': 'https://example.com/acme/',
                 'hardware_bound': True,
                 'key_size': 256,
                 'key_type': 'ECSECPrimeRandom',
                 'name': name,
                 'okta_ca_kwargs': {
                     'url': 'https://example.com/ndes/',
                     'username': 'yolo',
                     'password': 'fomo',
                 },
                 'usage_flags': 5}
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        acme_issuer = ACMEIssuer.objects.get(name=name)
        self.assertEqual(
            data,
            {'attest': True,
             'backend': 'OKTA_CA',
             'created_at': acme_issuer.created_at.isoformat(),
             'description': 'description',
             'directory_url': 'https://example.com/acme/',
             'extended_key_usage': [],
             'id': str(acme_issuer.pk),
             'hardware_bound': True,
             'key_size': 256,
             'key_type': 'ECSECPrimeRandom',
             'name': name,
             'okta_ca_kwargs': {'password': 'fomo',
                                'url': 'https://example.com/ndes/',
                                'username': 'yolo'},
             'provisioning_uid': None,
             'updated_at': acme_issuer.updated_at.isoformat(),
             'usage_flags': 5,
             'version': 1}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'created',
             'object': {
                 'model': 'mdm.acmeissuer',
                 'new_value': {
                     'attest': True,
                     'backend': 'OKTA_CA',
                     'backend_kwargs': {'password_hash': (
                                            '48ffcddb8b19a5f98d4b1b8c08b4024b12b6f24affeb50b1265aed528a2dd671'
                                        ),
                                        'url': 'https://example.com/ndes/',
                                        'username': 'yolo'},
                     'created_at': acme_issuer.created_at,
                     'description': 'description',
                     'directory_url': acme_issuer.directory_url,
                     'extended_key_usage': [],
                     'hardware_bound': True,
                     'key_size': 256,
                     'key_type': 'ECSECPrimeRandom',
                     'name': acme_issuer.name,
                     'pk': str(acme_issuer.pk),
                     'updated_at': acme_issuer.updated_at,
                     'usage_flags': 5,
                     'version': 1
                 },
                 'pk': str(acme_issuer.pk)}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_acme_issuer": [str(acme_issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_acme_issuer_ident(self, post_event):
        self.set_permissions("mdm.add_acmeissuer")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:acme_issuers"),
                {'attest': True,
                 'backend': 'IDENT',
                 'description': 'description',
                 'directory_url': 'https://example.com/acme/',
                 'hardware_bound': True,
                 'ident_kwargs': {
                     'url': 'https://example.com/ident/',
                     'bearer_token': 'YoloFomo',
                 },
                 'key_size': 256,
                 'key_type': 'ECSECPrimeRandom',
                 'name': name,
                 'usage_flags': 5}
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        acme_issuer = ACMEIssuer.objects.get(name=name)
        self.assertEqual(
            data,
            {'attest': True,
             'backend': 'IDENT',
             'created_at': acme_issuer.created_at.isoformat(),
             'description': 'description',
             'directory_url': 'https://example.com/acme/',
             'extended_key_usage': [],
             'id': str(acme_issuer.pk),
             'ident_kwargs': {
                 'url': 'https://example.com/ident/',
                 'bearer_token': 'YoloFomo',
                 'request_timeout': 30,
                 'max_retries': 3,
             },
             'hardware_bound': True,
             'key_size': 256,
             'key_type': 'ECSECPrimeRandom',
             'name': name,
             'provisioning_uid': None,
             'updated_at': acme_issuer.updated_at.isoformat(),
             'usage_flags': 5,
             'version': 1}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'created',
             'object': {
                 'model': 'mdm.acmeissuer',
                 'new_value': {
                     'attest': True,
                     'backend': 'IDENT',
                     'backend_kwargs': {'bearer_token_hash': (
                                            '69fd1658dc95ce930f492232866e1c980ac3fb4e4319a8189b141be3d18a6a33'
                                        ),
                                        'max_retries': 3,
                                        'request_timeout': 30,
                                        'url': 'https://example.com/ident/'},
                     'created_at': acme_issuer.created_at,
                     'description': 'description',
                     'directory_url': acme_issuer.directory_url,
                     'extended_key_usage': [],
                     'hardware_bound': True,
                     'key_size': 256,
                     'key_type': 'ECSECPrimeRandom',
                     'name': acme_issuer.name,
                     'pk': str(acme_issuer.pk),
                     'updated_at': acme_issuer.updated_at,
                     'usage_flags': 5,
                     'version': 1
                 },
                 'pk': str(acme_issuer.pk)}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_acme_issuer": [str(acme_issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # update acme_issuer

    def test_update_acme_issuer_unauthorized(self):
        acme_issuer = force_acme_issuer()
        response = self.put(reverse("mdm_api:acme_issuer", args=(acme_issuer.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_acme_issuer_permission_denied(self):
        acme_issuer = force_acme_issuer()
        response = self.put(reverse("mdm_api:acme_issuer", args=(acme_issuer.pk,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_acme_issuer_cannot_be_updated(self):
        acme_issuer = force_acme_issuer(provisioning_uid=get_random_string(12))
        self.set_permissions("mdm.change_acmeissuer")
        response = self.put(
            reverse("mdm_api:acme_issuer", args=(acme_issuer.pk,)),
            {'attest': False,
             'backend': 'STATIC_CHALLENGE',
             'description': 'description',
             'directory_url': acme_issuer.directory_url,
             'extended_key_usage': [
                 '1.3.6.1.5.5.7.3.2',
             ],
             'hardware_bound': False,
             'key_size': 2048,
             'key_type': 'RSA',
             'name': get_random_string(12),
             'static_challenge_kwargs': {
                 'challenge': 'fomo',
             },
             'usage_flags': 1}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['This ACME issuer cannot be updated.'])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_acme_issuer(self, post_event):
        acme_issuer = force_acme_issuer()
        prev_value = acme_issuer.serialize_for_event()
        new_name = get_random_string(12)
        self.set_permissions("mdm.change_acmeissuer")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(
                reverse("mdm_api:acme_issuer", args=(acme_issuer.pk,)),
                {'attest': False,
                 'backend': 'STATIC_CHALLENGE',
                 'description': 'description',
                 'directory_url': acme_issuer.directory_url,
                 'extended_key_usage': [
                     '1.3.6.1.5.5.7.3.2',
                 ],
                 'hardware_bound': False,
                 'key_size': 2048,
                 'key_type': 'RSA',
                 'name': new_name,
                 'static_challenge_kwargs': {
                     'challenge': 'fomo',
                 },
                 'usage_flags': 1}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        acme_issuer.refresh_from_db()
        self.assertEqual(
            data,
            {'attest': False,
             'backend': 'STATIC_CHALLENGE',
             'created_at': acme_issuer.created_at.isoformat(),
             'description': 'description',
             'directory_url': acme_issuer.directory_url,
             'extended_key_usage': [
                 '1.3.6.1.5.5.7.3.2',
             ],
             'hardware_bound': False,
             'id': str(acme_issuer.pk),
             'key_size': 2048,
             'key_type': 'RSA',
             'name': acme_issuer.name,
             'provisioning_uid': None,
             'static_challenge_kwargs': {
                 'challenge': 'fomo',
             },
             'updated_at': acme_issuer.updated_at.isoformat(),
             'usage_flags': 1,
             'version': 2}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'updated',
             'object': {
                 'model': 'mdm.acmeissuer',
                 'new_value': {
                     'attest': False,
                     'backend': 'STATIC_CHALLENGE',
                     'backend_kwargs': {'challenge_hash': (
                                            '48ffcddb8b19a5f98d4b1b8c08b4024b12b6f24affeb50b1265aed528a2dd671'
                                        )},
                     'created_at': acme_issuer.created_at,
                     'description': 'description',
                     'directory_url': acme_issuer.directory_url,
                     'extended_key_usage': [
                         '1.3.6.1.5.5.7.3.2',
                     ],
                     'hardware_bound': False,
                     'key_size': 2048,
                     'key_type': 'RSA',
                     'name': acme_issuer.name,
                     'pk': str(acme_issuer.pk),
                     'updated_at': acme_issuer.updated_at,
                     'usage_flags': 1,
                     'version': 2
                 },
                 'pk': str(acme_issuer.pk),
                 'prev_value': prev_value}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_acme_issuer": [str(acme_issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # delete acme_issuer

    def test_delete_acme_issuer_unauthorized(self):
        acme_issuer = force_acme_issuer()
        response = self.delete(reverse("mdm_api:acme_issuer", args=(acme_issuer.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_acme_issuer_permission_denied(self):
        acme_issuer = force_acme_issuer()
        response = self.delete(reverse("mdm_api:acme_issuer", args=(acme_issuer.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_acme_issuer_cannot_be_deleted(self):
        dep_enrollment = force_dep_enrollment(self.mbu, acme_issuer=True)
        self.set_permissions("mdm.delete_acmeissuer")
        response = self.delete(reverse("mdm_api:acme_issuer", args=(dep_enrollment.acme_issuer.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['This ACME issuer cannot be deleted.'])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_acme_issuer(self, post_event):
        acme_issuer = force_acme_issuer()
        prev_value = acme_issuer.serialize_for_event()
        self.set_permissions("mdm.delete_acmeissuer")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:acme_issuer", args=(acme_issuer.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.acmeissuer",
                 "pk": str(acme_issuer.pk),
                 "prev_value": prev_value,
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_acme_issuer": [str(acme_issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
