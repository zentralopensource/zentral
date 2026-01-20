from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.mdm.models import OTAEnrollment
from zentral.core.events.base import AuditEvent
from .utils import (force_acme_issuer, force_blueprint, force_ota_enrollment, force_ota_enrollment_session,
                    force_push_certificate, force_realm, force_scep_issuer)


class MDMOTAEnrollmentsAPIViewsTestCase(TestCase):
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

    # list OTA enrollments

    def test_list_ota_enrollments_unauthorized(self):
        response = self.get(reverse("mdm_api:ota_enrollments"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_ota_enrollments_permission_denied(self):
        response = self.get(reverse("mdm_api:ota_enrollments"))
        self.assertEqual(response.status_code, 403)

    def test_list_ota_enrollments(self):
        realm = force_realm()
        oe = force_ota_enrollment(realm=realm)
        self.set_permissions("mdm.view_otaenrollment")
        response = self.get(reverse("mdm_api:ota_enrollments"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'blueprint': None,
              'created_at': oe.created_at.isoformat(),
              'display_name': oe.display_name,
              'enrollment_secret': {
                  'id': oe.enrollment_secret.pk,
                  'meta_business_unit': oe.enrollment_secret.meta_business_unit.pk,
                  'quota': None,
                  'request_count': 0,
                  'secret': oe.enrollment_secret.secret,
                  'serial_numbers': None,
                  'tags': [],
                  'udids': None
              },
              'id': oe.pk,
              'name': oe.name,
              'push_certificate': oe.push_certificate.pk,
              'realm': str(realm.pk),
              'acme_issuer': str(oe.acme_issuer.pk),
              'scep_issuer': str(oe.scep_issuer.pk),
              'updated_at': oe.updated_at.isoformat()}]
        )

    def test_list_ota_enrollments_name_filter(self):
        force_ota_enrollment()
        oe = force_ota_enrollment()
        self.set_permissions("mdm.view_otaenrollment")
        response = self.get(reverse("mdm_api:ota_enrollments"), data={"name": oe.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'blueprint': None,
              'created_at': oe.created_at.isoformat(),
              'display_name': oe.display_name,
              'enrollment_secret': {
                  'id': oe.enrollment_secret.pk,
                  'meta_business_unit': oe.enrollment_secret.meta_business_unit.pk,
                  'quota': None,
                  'request_count': 0,
                  'secret': oe.enrollment_secret.secret,
                  'serial_numbers': None,
                  'tags': [],
                  'udids': None
              },
              'id': oe.pk,
              'name': oe.name,
              'push_certificate': oe.push_certificate.pk,
              'realm': None,
              'acme_issuer': str(oe.acme_issuer.pk),
              'scep_issuer': str(oe.scep_issuer.pk),
              'updated_at': oe.updated_at.isoformat()}]
        )

    # get OTA enrollment

    def test_get_ota_enrollment_unauthorized(self):
        oe = force_ota_enrollment()
        response = self.get(reverse("mdm_api:ota_enrollment", args=(oe.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_ota_enrollment_permission_denied(self):
        oe = force_ota_enrollment()
        response = self.get(reverse("mdm_api:blueprint", args=(oe.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_ota_enrollment(self):
        force_ota_enrollment()
        oe = force_ota_enrollment()
        self.set_permissions("mdm.view_otaenrollment")
        response = self.get(reverse("mdm_api:ota_enrollment", args=(oe.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'blueprint': None,
             'created_at': oe.created_at.isoformat(),
             'display_name': oe.display_name,
             'enrollment_secret': {
                 'id': oe.enrollment_secret.pk,
                 'meta_business_unit': oe.enrollment_secret.meta_business_unit.pk,
                 'quota': None,
                 'request_count': 0,
                 'secret': oe.enrollment_secret.secret,
                 'serial_numbers': None,
                 'tags': [],
                 'udids': None
             },
             'id': oe.pk,
             'name': oe.name,
             'push_certificate': oe.push_certificate.pk,
             'realm': None,
             'acme_issuer': str(oe.acme_issuer.pk),
             'scep_issuer': str(oe.scep_issuer.pk),
             'updated_at': oe.updated_at.isoformat()}
        )

    # create OTA enrollment

    def test_create_ota_enrollment_unauthorized(self):
        response = self.post(reverse("mdm_api:ota_enrollments"),
                             {"name": get_random_string(12)},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_ota_enrollment_permission_denied(self):
        response = self.post(reverse("mdm_api:ota_enrollments"),
                             {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 403)

    def test_create_ota_enrollment_required_fields(self):
        self.set_permissions("mdm.add_otaenrollment")
        response = self.post(reverse("mdm_api:ota_enrollments"), {})
        self.assertEqual(
            response.json(),
            {'enrollment_secret': ['This field is required.'],
             'name': ['This field is required.'],
             'push_certificate': ['This field is required.'],
             'scep_issuer': ['This field is required.']}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_ota_enrollment(self, post_event):
        self.set_permissions("mdm.add_otaenrollment")
        name = get_random_string(12)
        blueprint = force_blueprint()
        push_certificate = force_push_certificate()
        realm = force_realm()
        acme_issuer = force_acme_issuer()
        scep_issuer = force_scep_issuer()
        tags = sorted((Tag.objects.create(name=get_random_string(12)) for _ in range(2)), key=lambda t: t.pk)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:ota_enrollments"),
                                 {"blueprint": blueprint.pk,
                                  "enrollment_secret": {
                                     "meta_business_unit": self.mbu.pk,
                                     "tags":  [t.id for t in tags],
                                  },
                                  "name": name,
                                  "push_certificate": push_certificate.pk,
                                  "realm": str(realm.pk),
                                  "acme_issuer": str(acme_issuer.pk),
                                  "scep_issuer": str(scep_issuer.pk)})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        oe = OTAEnrollment.objects.get(name=name)
        self.assertEqual(oe.blueprint, blueprint)
        self.assertEqual(oe.enrollment_secret.meta_business_unit, self.mbu)
        self.assertEqual(
            set(oe.enrollment_secret.tags.all()),
            set(tags)
        )
        self.assertEqual(oe.name, name)
        self.assertEqual(oe.push_certificate, push_certificate)
        self.assertEqual(oe.acme_issuer, acme_issuer)
        self.assertEqual(oe.scep_issuer, scep_issuer)
        response_json = response.json()
        response_json['enrollment_secret']['tags'].sort()
        self.assertEqual(
            response.json(),
            {'blueprint': blueprint.pk,
             'created_at': oe.created_at.isoformat(),
             'display_name': oe.display_name,
             'enrollment_secret': {
                 'id': oe.enrollment_secret.pk,
                 'meta_business_unit': self.mbu.pk,
                 'quota': None,
                 'request_count': 0,
                 'secret': oe.enrollment_secret.secret,
                 'serial_numbers': None,
                 'tags': sorted([t.id for t in tags]),
                 'udids': None
             },
             'id': oe.pk,
             'name': name,
             'push_certificate': push_certificate.pk,
             'realm': str(realm.pk),
             'acme_issuer': str(acme_issuer.pk),
             'scep_issuer': str(scep_issuer.pk),
             'updated_at': oe.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        event.payload["object"]["new_value"]["enrollment_secret"]["tags"].sort(key=lambda t: t["pk"])
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.otaenrollment",
                 "pk": str(oe.pk),
                 "new_value": {
                     'created_at': oe.created_at,
                     'enrollment_secret': {
                         'created_at': oe.enrollment_secret.created_at,
                         'is_expired': False,
                         'is_revoked': False,
                         'is_used_up': False,
                         'meta_business_unit': {'name': self.mbu.name,
                                                'pk': self.mbu.pk},
                         'pk': oe.enrollment_secret.pk,
                         'request_count': 0,
                         'tags': [{'name': t.name, 'pk': t.pk} for t in tags],
                     },
                     'name': oe.name,
                     'pk': oe.pk,
                     'realm': {
                         'pk': str(realm.pk),
                         'name': realm.name,
                     },
                     'updated_at': oe.updated_at,
                 }
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_ota_enrollment": [str(oe.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # update OTA enrollment

    def test_update_ota_enrollment_unauthorized(self):
        oe = force_ota_enrollment()
        response = self.put(reverse("mdm_api:ota_enrollment", args=(oe.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_ota_enrollment_permission_denied(self):
        oe = force_ota_enrollment()
        response = self.put(reverse("mdm_api:ota_enrollment", args=(oe.pk,)), {})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_ota_enrollment(self, post_event):
        oe = force_ota_enrollment()
        prev_value = oe.serialize_for_event()
        self.set_permissions("mdm.change_otaenrollment")
        new_name = get_random_string(12)
        new_blueprint = force_blueprint()
        new_push_certificate = force_push_certificate()
        new_acme_issuer = force_acme_issuer()
        new_scep_issuer = force_scep_issuer()
        new_tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(1)]
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("mdm_api:ota_enrollment", args=(oe.pk,)),
                                {"blueprint": new_blueprint.pk,
                                 "enrollment_secret": {
                                    "meta_business_unit": self.mbu.pk,
                                    "tags":  [t.id for t in new_tags],
                                 },
                                 "name": new_name,
                                 "push_certificate": new_push_certificate.pk,
                                 "acme_issuer": str(new_acme_issuer.pk),
                                 "scep_issuer": str(new_scep_issuer.pk)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        oe.refresh_from_db()
        self.assertEqual(oe.blueprint, new_blueprint)
        self.assertEqual(oe.enrollment_secret.meta_business_unit, self.mbu)
        self.assertEqual(
            set(oe.enrollment_secret.tags.all()),
            set(new_tags)
        )
        self.assertEqual(oe.name, new_name)
        self.assertEqual(oe.push_certificate, new_push_certificate)
        self.assertEqual(oe.acme_issuer, new_acme_issuer)
        self.assertEqual(oe.scep_issuer, new_scep_issuer)
        response_json = response.json()
        response_json['enrollment_secret']['tags'].sort()
        self.assertEqual(
            response.json(),
            {'blueprint': new_blueprint.pk,
             'created_at': oe.created_at.isoformat(),
             'display_name': oe.display_name,
             'enrollment_secret': {
                 'id': oe.enrollment_secret.pk,
                 'meta_business_unit': self.mbu.pk,
                 'quota': None,
                 'request_count': 0,
                 'secret': oe.enrollment_secret.secret,
                 'serial_numbers': None,
                 'tags': sorted([t.id for t in new_tags]),
                 'udids': None
             },
             'id': oe.pk,
             'name': new_name,
             'push_certificate': new_push_certificate.pk,
             'realm': None,
             'acme_issuer': str(new_acme_issuer.pk),
             'scep_issuer': str(new_scep_issuer.pk),
             'updated_at': oe.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        event.payload["object"]["new_value"]["enrollment_secret"]["tags"].sort(key=lambda t: t["pk"])
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.otaenrollment",
                 "pk": str(oe.pk),
                 "new_value": {
                     'created_at': oe.created_at,
                     'enrollment_secret': {
                         'created_at': oe.enrollment_secret.created_at,
                         'is_expired': False,
                         'is_revoked': False,
                         'is_used_up': False,
                         'meta_business_unit': {'name': self.mbu.name,
                                                'pk': self.mbu.pk},
                         'pk': oe.enrollment_secret.pk,
                         'request_count': 0,
                         'tags': [{'name': t.name, 'pk': t.pk} for t in new_tags],
                     },
                     'name': new_name,
                     'pk': oe.pk,
                     'realm': None,
                     'updated_at': oe.updated_at,
                 },
                 "prev_value": prev_value,
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_ota_enrollment": [str(oe.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # delete software update enforcement

    def test_delete_ota_enrollment_unauthorized(self):
        oe = force_ota_enrollment()
        response = self.delete(reverse("mdm_api:ota_enrollment", args=(oe.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_ota_enrollment_permission_denied(self):
        oe = force_ota_enrollment()
        response = self.delete(reverse("mdm_api:ota_enrollment", args=(oe.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_ota_enrollment_cannot_be_deleted(self):
        oes, _, _ = force_ota_enrollment_session(self.mbu)
        self.set_permissions("mdm.delete_otaenrollment")
        response = self.delete(reverse("mdm_api:ota_enrollment", args=(oes.ota_enrollment.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This OTA enrollment cannot be deleted"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_ota_enrollment(self, post_event):
        oe = force_ota_enrollment()
        prev_value = oe.serialize_for_event()
        self.set_permissions("mdm.delete_otaenrollment")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:ota_enrollment", args=(oe.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(OTAEnrollment.objects.filter(name=oe.name).count(), 0)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.otaenrollment",
                 "pk": str(oe.pk),
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_ota_enrollment": [str(oe.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
