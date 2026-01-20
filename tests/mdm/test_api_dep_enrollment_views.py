
from functools import reduce
import operator
import uuid
from unittest.mock import patch
from urllib.parse import urlencode
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.urls import reverse
from accounts.models import User, APIToken
from realms.models import Realm
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import (DEPEnrollment, DEPEnrollmentCustomView, DEPEnrollmentSession,
                                        DEPVirtualServer, EnrollmentCustomView)
from .utils import (force_dep_enrollment, force_push_certificate, force_acme_issuer,
                    force_scep_issuer, force_dep_virtual_server, force_realm, force_enrollment_custom_view)
from zentral.contrib.mdm.skip_keys import skippable_setup_panes
from zentral.core.events.base import AuditEvent
from zentral.contrib.inventory.models import Tag
from datetime import timedelta


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class ApiViewsTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        # user
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.com", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])

        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)

    # utils
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

    def get(self, *args, **kwargs):
        return self._make_request(self.client.get, *args, **kwargs)

    def post(self, url, data=None, include_token=True, *args, **kwargs):
        return self._make_request(self.client.post, url, data, include_token=include_token, *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._make_request(self.client.put, *args, **kwargs)

    def delete(self, *args, **kwargs):
        return self._make_request(self.client.delete, *args, **kwargs)

    def _given_tag(self):
        return Tag.objects.create(
            name=f"tag_{get_random_string(5)}"
        )

    def _given_dep_enrollment_custom_view(self):
        view = force_enrollment_custom_view()
        enrollment = force_dep_enrollment(self.mbu)
        return DEPEnrollmentCustomView.objects.create(
            dep_enrollment=enrollment,
            custom_view=view
        )

    def _given_ordered_entity_list(self, factory):
        entity = None
        now = timezone.now()
        for i in range(3):
            e = factory()
            e.created_at = now - timedelta(hours=2-i)
            e.save()
            if i == 1:
                entity = e
        return entity

    def _virtual_server_to_dict(self, virtual_server: DEPVirtualServer):
        return {
            'id': virtual_server.id,
            'name': virtual_server.name,
            'uuid': str(virtual_server.uuid),
            'created_at': virtual_server.created_at.isoformat(),
            'updated_at': virtual_server.updated_at.isoformat()
        }

    def _virtual_server_to_list(
            self, virtual_server: DEPVirtualServer = None, count: int = 0, next: str = None, previous: str = None):
        return {
            'count': count,
            'next': next,
            'previous': previous,
            'results': [] if virtual_server is None else [self._virtual_server_to_dict(virtual_server)]
        }

    def _dep_enrollment_to_dict(self, enrollment: DEPEnrollment):
        return {
            'id': enrollment.id,
            'enrollment_secret': {
                'id': enrollment.enrollment_secret.id,
                'secret': enrollment.enrollment_secret.secret,
                'meta_business_unit': enrollment.enrollment_secret.meta_business_unit.id,
                'tags': [tag.id for tag in enrollment.enrollment_secret.tags.all()],
                'serial_numbers': enrollment.enrollment_secret.serial_numbers,
                'udids': enrollment.enrollment_secret.udids,
                'quota': enrollment.enrollment_secret.quota,
                'request_count': enrollment.enrollment_secret.request_count
            },
            'display_name': enrollment.display_name,
            'use_realm_user': enrollment.use_realm_user,
            'username_pattern': enrollment.username_pattern,
            'realm_user_is_admin': enrollment.realm_user_is_admin,
            'admin_full_name': enrollment.admin_full_name,
            'admin_short_name': enrollment.admin_short_name,
            'hidden_admin': enrollment.hidden_admin,
            'admin_password_complexity': enrollment.admin_password_complexity,
            'admin_password_rotation_delay': enrollment.admin_password_rotation_delay,
            'name': enrollment.name,
            'allow_pairing': enrollment.allow_pairing,
            'auto_advance_setup': enrollment.auto_advance_setup,
            'await_device_configured': enrollment.await_device_configured,
            'department': enrollment.department,
            'is_mandatory': enrollment.is_mandatory,
            'is_mdm_removable': enrollment.is_mdm_removable,
            'is_multi_user': enrollment.is_multi_user,
            'is_supervised': enrollment.is_supervised,
            'language': enrollment.language,
            'org_magic': enrollment.org_magic,
            'region': enrollment.region,
            'skip_setup_items': enrollment.skip_setup_items,
            'support_email_address': enrollment.support_email_address,
            'support_phone_number': enrollment.support_phone_number,
            'include_tls_certificates': enrollment.include_tls_certificates,
            'ios_max_version': enrollment.ios_max_version,
            'ios_min_version': enrollment.ios_min_version,
            'macos_max_version': enrollment.macos_max_version,
            'macos_min_version': enrollment.macos_min_version,
            'push_certificate': enrollment.push_certificate.id if enrollment.push_certificate else None,
            'acme_issuer': str(enrollment.acme_issuer.id) if enrollment.acme_issuer else None,
            'scep_issuer': str(enrollment.scep_issuer.id) if enrollment.scep_issuer else None,
            'blueprint': enrollment.blueprint.id if enrollment.blueprint else None,
            'realm': enrollment.realm.id if enrollment.realm else None,
            'virtual_server': enrollment.virtual_server.id
            }

    def _dep_enrollment_to_list(
            self, enrollment: DEPEnrollment = None, count: int = 0, next: str = None, previous: str = None):
        return {
            'count': count,
            'next': next,
            'previous': previous,
            'results': [] if enrollment is None else [self._dep_enrollment_to_dict(enrollment)]
        }

    def _enrollment_custom_view_to_dict(self, view: EnrollmentCustomView):
        return {
            'description': view.description,
            'html': view.html,
            'id': str(view.id),
            'name': view.name,
            'requires_authentication': view.requires_authentication
        }

    def _enrollment_custom_view_to_list(
            self, view: EnrollmentCustomView = None, count: int = 0, next: str = None, previous: str = None):
        return {
            'count': count,
            'next': next,
            'previous': previous,
            'results': [] if view is None else [self._enrollment_custom_view_to_dict(view)]
        }

    def _dep_enrollment_custom_view_to_dict(self, view: DEPEnrollmentCustomView):
        return {
            "id": str(view.id),
            "custom_view": str(view.custom_view.pk),
            "dep_enrollment": view.dep_enrollment.id,
            "weight": view.weight
        }

    def _dep_enrollment_custom_view_to_list(
            self, view: DEPEnrollmentCustomView = None, count: int = 0, next: str = None, previous: str = None):
        return {
            'count': count,
            'next': next,
            'previous': previous,
            'results': [] if view is None else [self._dep_enrollment_custom_view_to_dict(view)]
        }

    def _create_dep_enrollment_request(self,
                                       tag: Tag = None,
                                       is_mdm_removable: bool = True,
                                       realm: Realm = None,
                                       use_realm_user: bool = False,
                                       username_pattern: str = "",
                                       realm_user_is_admin: bool = False,
                                       ios_max_version: str = "1.2.3",
                                       ios_min_version: str = "1.2.3",
                                       macos_max_version: str = "1.2.3",
                                       macos_min_version: str = "1.2.3",
                                       admin_full_name: str = None,
                                       admin_short_name: str = None,
                                       await_device_configured: bool = True,
                                       skip_setup_item: str = None,
                                       language: str = ""):
        return {
            'display_name': get_random_string(12),
            'name': get_random_string(12),
            'push_certificate': str(force_push_certificate().id),
            'acme_issuer': str(force_acme_issuer().id),
            'scep_issuer': str(force_scep_issuer().id),
            'virtual_server': force_dep_virtual_server().id,
            'enrollment_secret': {
                'meta_business_unit': self.mbu.id,
                'tags': [tag.id] if tag else [],
                'serial_numbers': [get_random_string(12)],
                'udids': [str(uuid.uuid4())]
            },
            'skip_setup_items': [skip_setup_item] if skip_setup_item else [k for k, _ in skippable_setup_panes],
            'is_mdm_removable': is_mdm_removable,
            'is_supervised': False,
            'realm': realm.pk if realm else None,
            'use_realm_user': use_realm_user,
            'username_pattern': username_pattern,
            'realm_user_is_admin': realm_user_is_admin,
            'ios_max_version': ios_max_version,
            'ios_min_version': ios_min_version,
            'macos_max_version': macos_max_version,
            'macos_min_version': macos_min_version,
            'admin_full_name': admin_full_name,
            'admin_short_name': admin_short_name,
            'await_device_configured': await_device_configured,
            'language': language
        }

    def _create_enrollment_custom_view_request(self):
        return {
            "name":  get_random_string(12),
            "description": get_random_string(20),
            "html": get_random_string(128),
            "requires_authentication": False
        }

    def _create_dep_enrollment_custom_view_request(
            self,
            weight: int = 0,
            custom_view: EnrollmentCustomView = None, 
            dep_enrollment: DEPEnrollment = None):
        if not custom_view:
            custom_view = force_enrollment_custom_view()
        if not dep_enrollment:
            dep_enrollment = force_dep_enrollment(self.mbu)
        return {
            "custom_view": str(custom_view.pk),
            "dep_enrollment": dep_enrollment.id,
            "weight": weight
        }

    def _assert_audit_event_send(self, instance, post_event, callbacks,
                                 action: AuditEvent.Action, prev_value: dict[str, str] = None):
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]

        if isinstance(instance, DEPEnrollment):
            model = 'mdm.depenrollment'
            objects = 'mdm_dep_enrollment'
        elif isinstance(instance, EnrollmentCustomView):
            model = 'mdm.enrollmentcustomview'
            objects = 'mdm_enrollment_custom_view'
        elif isinstance(instance, DEPEnrollmentCustomView):
            model = 'mdm.depenrollmentcustomview'
            objects = 'mdm_dep_enrollment_custom_view'

        expected_payload = {'action': action.value,
                            'object': {
                                'model': model,
                                'pk': str(instance.pk)}}
        match action:
            case AuditEvent.Action.CREATED:
                expected_payload["object"].update({'new_value': instance.serialize_for_event()})
            case AuditEvent.Action.UPDATED:
                expected_payload["object"].update({'prev_value': prev_value})
                expected_payload["object"].update({'new_value': instance.serialize_for_event()})
            case AuditEvent.Action.DELETED:
                expected_payload["object"].update({'prev_value': prev_value})

        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            expected_payload
        )

        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {objects: [str(instance.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    def _assert_audit_event_not_send(self, post_event, callbacks):
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    def _assert_no_profil_added(self, add_profile):
        self.assertEqual(len(add_profile.call_args_list), 0)

    # List DEP virtual servers

    def test_list_dep_virtual_server_unauthorized(self):
        response = self.get(reverse("mdm_api:dep_virtual_servers"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_dep_virtual_server_permission_denied(self):
        response = self.get(reverse("mdm_api:dep_virtual_servers"))
        self.assertEqual(response.status_code, 403)

    def test_list_dep_virtual_server(self):
        self.set_permissions("mdm.view_depvirtualserver")
        virtual_server = force_dep_virtual_server()
        response = self.get(reverse("mdm_api:dep_virtual_servers"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._virtual_server_to_list(virtual_server, 1))

    def test_list_dep_virtual_server_by_name_no_results(self):
        self.set_permissions("mdm.view_depvirtualserver")
        response = self.get(reverse("mdm_api:dep_virtual_servers") + f"?name={get_random_string(12)}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), self._virtual_server_to_list())

    def test_list_dep_virtual_server_by_name(self):
        self.set_permissions("mdm.view_depvirtualserver")
        virtual_server = force_dep_virtual_server()
        response = self.get(reverse("mdm_api:dep_virtual_servers") + f"?name={virtual_server.name}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._virtual_server_to_list(virtual_server, 1))

    def test_list_dep_virtual_server_ordering(self):
        self.set_permissions("mdm.view_depvirtualserver")

        virtual_server = self._given_ordered_entity_list(lambda: force_dep_virtual_server())

        response = self.get(reverse("mdm_api:dep_virtual_servers")
                            + "?" + urlencode({"ordering": "-created_at",
                                               "limit": 1,
                                               "offset": 1}))
        self.assertEqual(DEPVirtualServer.objects.count(), 3)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._virtual_server_to_list(
                virtual_server=virtual_server,
                count=3,
                next='http://testserver/api/mdm/dep/virtual_servers/?limit=1&offset=2&ordering=-created_at',
                previous='http://testserver/api/mdm/dep/virtual_servers/?limit=1&ordering=-created_at')
        )

    # Get DEP virtual server

    def test_get_dep_virtual_server_unauthorized(self):
        virtual_server = force_dep_virtual_server()

        response = self.get(
            reverse("mdm_api:dep_virtual_server", args=(virtual_server.id, )),
            include_token=False
        )
        self.assertEqual(response.status_code, 401)

    def test_get_dep_virtual_server_permission_denied(self):
        virtual_server = force_dep_virtual_server()
        response = self.get(
            reverse("mdm_api:dep_virtual_server", args=(virtual_server.id, ))
        )
        self.assertEqual(response.status_code, 403)

    def test_get_dep_virtual_server(self):
        self.set_permissions("mdm.view_depvirtualserver")
        virtual_server = force_dep_virtual_server()

        response = self.get(reverse("mdm_api:dep_virtual_server", args=(virtual_server.id, )))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._virtual_server_to_dict(virtual_server)
        )

    # List DEP Enrollments

    def test_list_dep_enrollments_unauthorized(self):
        response = self.get(reverse("mdm_api:dep_enrollments"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_dep_enrollments_permission_denied(self):
        response = self.get(reverse("mdm_api:dep_enrollments"))
        self.assertEqual(response.status_code, 403)

    def test_list_dep_enrollments(self):
        self.set_permissions("mdm.view_depenrollment")
        enrollment = force_dep_enrollment(self.mbu)
        response = self.get(reverse("mdm_api:dep_enrollments"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._dep_enrollment_to_list(enrollment, 1))

    def test_list_dep_enrollments_by_name_no_results(self):
        self.set_permissions("mdm.view_depenrollment")
        response = self.get(reverse("mdm_api:dep_enrollments") + f"?name={get_random_string(12)}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), self._dep_enrollment_to_list())

    def test_list_dep_enrollments_by_name(self):
        self.set_permissions("mdm.view_depenrollment")
        enrollment = force_dep_enrollment(self.mbu)
        response = self.get(reverse("mdm_api:dep_enrollments") + f"?name={enrollment.name}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._dep_enrollment_to_list(enrollment, 1))

    def test_list_dep_enrollments_ordering(self):
        self.set_permissions("mdm.view_depenrollment")

        enrollment = self._given_ordered_entity_list(lambda: force_dep_enrollment(self.mbu))

        response = self.get(reverse("mdm_api:dep_enrollments")
                            + "?" + urlencode({"ordering": "-created_at",
                                               "limit": 1,
                                               "offset": 1}))
        self.assertEqual(DEPEnrollment.objects.count(), 3)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._dep_enrollment_to_list(
                enrollment=enrollment,
                count=3,
                next='http://testserver/api/mdm/dep_enrollments/?limit=1&offset=2&ordering=-created_at',
                previous='http://testserver/api/mdm/dep_enrollments/?limit=1&ordering=-created_at')
        )

    # Get DEP enrollment

    def test_get_dep_enrollment_unauthorized(self):
        enrollment = force_dep_enrollment(self.mbu)

        response = self.get(
            reverse("mdm_api:dep_enrollment", args=(enrollment.id, )),
            include_token=False
        )
        self.assertEqual(response.status_code, 401)

    def test_get_dep_enrollment_permission_denied(self):
        enrollment = force_dep_enrollment(self.mbu)
        response = self.get(reverse("mdm_api:dep_enrollment", args=(enrollment.id, )))
        self.assertEqual(response.status_code, 403)

    def test_get_dep_enrollment(self):
        self.set_permissions("mdm.view_depenrollment")
        enrollment = force_dep_enrollment(self.mbu, language="en")

        response = self.get(reverse("mdm_api:dep_enrollment", args=(enrollment.id, )))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._dep_enrollment_to_dict(enrollment)
        )

    # Create DEP Enrollment

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    def test_create_dep_enrollment_unauthorized(self, add_profile):
        request = self._create_dep_enrollment_request(is_mdm_removable=False)
        add_profile.side_effect = Exception()
        response = self.post(
                reverse("mdm_api:dep_enrollments"),
                request,
                include_token=False
            )
        self.assertEqual(response.status_code, 401)
        self._assert_no_profil_added(add_profile)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    def test_create_dep_enrollment_permission_denied(self, add_profile):
        request = self._create_dep_enrollment_request(is_mdm_removable=False)
        add_profile.side_effect = Exception()
        response = self.post(
                reverse("mdm_api:dep_enrollments"),
                request
            )
        self.assertEqual(response.status_code, 403)
        self._assert_no_profil_added(add_profile)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment_validate_is_mdm_removable(self, post_event, add_profile):
        self.set_permissions("mdm.add_depenrollment")
        request = self._create_dep_enrollment_request(is_mdm_removable=False)
        add_profile.side_effect = Exception()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:dep_enrollments"),
                request
            )

        self.assertFalse(DEPEnrollment.objects.filter(name=request["name"]).exists())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"is_mdm_removable": ["Can only be set to False if 'Is supervised' is set to True"]}
        )

        self._assert_no_profil_added(add_profile)
        self._assert_audit_event_not_send(post_event, callbacks)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment_validate_use_realm_user(self, post_event, add_profile):
        self.set_permissions("mdm.add_depenrollment")
        request = self._create_dep_enrollment_request(
            use_realm_user=True,
            username_pattern=DEPEnrollment.UsernamePattern.EMAIL_PREFIX
        )
        add_profile.side_effect = Exception()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:dep_enrollments"),
                request
            )

        self.assertFalse(DEPEnrollment.objects.filter(name=request["name"]).exists())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"use_realm_user": ["This option is only valid if a 'realm' is selected"]}
        )

        self._assert_no_profil_added(add_profile)
        self._assert_audit_event_not_send(post_event, callbacks)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment_validate_username_pattern(self, post_event, add_profile):
        self.set_permissions("mdm.add_depenrollment")
        realm = force_realm()
        request = self._create_dep_enrollment_request(
            realm=realm, use_realm_user=False, username_pattern=DEPEnrollment.UsernamePattern.EMAIL_PREFIX)
        add_profile.side_effect = Exception()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:dep_enrollments"),
                request
            )

        self.assertFalse(DEPEnrollment.objects.filter(name=request["name"]).exists())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"username_pattern": ["This field can only be used if the 'use realm user' option is ticked"]}
        )

        self._assert_no_profil_added(add_profile)
        self._assert_audit_event_not_send(post_event, callbacks)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment_validate_username_pattern_required(self, post_event, add_profile):
        self.set_permissions("mdm.add_depenrollment")
        realm = force_realm()
        request = self._create_dep_enrollment_request(
            realm=realm, use_realm_user=True, username_pattern="")
        add_profile.side_effect = Exception()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:dep_enrollments"),
                request
            )

        self.assertFalse(DEPEnrollment.objects.filter(name=request["name"]).exists())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"username_pattern": ["This field is required when the 'use realm user' option is ticked"]}
        )

        self._assert_no_profil_added(add_profile)
        self._assert_audit_event_not_send(post_event, callbacks)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment_validate_realm_user_is_admin(self, post_event, add_profile):
        self.set_permissions("mdm.add_depenrollment")
        request = self._create_dep_enrollment_request(
            use_realm_user=False, realm_user_is_admin=True)
        add_profile.side_effect = Exception()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:dep_enrollments"),
                request
            )

        self.assertFalse(DEPEnrollment.objects.filter(name=request["name"]).exists())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"realm_user_is_admin": ["This option is only valid if the 'use realm user' option is ticked too"]}
        )

        self._assert_no_profil_added(add_profile)
        self._assert_audit_event_not_send(post_event, callbacks)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment_validate_os_version(self, post_event, add_profile):
        self.set_permissions("mdm.add_depenrollment")
        request = self._create_dep_enrollment_request(
            ios_max_version=get_random_string(12))
        add_profile.side_effect = Exception()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:dep_enrollments"),
                request
            )

        self.assertFalse(DEPEnrollment.objects.filter(name=request["name"]).exists())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"ios_max_version": ["Not a valid OS version"]}
        )

        self._assert_no_profil_added(add_profile)
        self._assert_audit_event_not_send(post_event, callbacks)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment_validate_admin_full_name(self, post_event, add_profile):
        self.set_permissions("mdm.add_depenrollment")
        request = self._create_dep_enrollment_request(
            admin_full_name=None, admin_short_name=get_random_string(12))
        add_profile.side_effect = Exception()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:dep_enrollments"),
                request
            )

        self.assertFalse(DEPEnrollment.objects.filter(name=request["name"]).exists())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"admin_full_name": ["Auto admin information incomplete"]}
        )

        self._assert_no_profil_added(add_profile)
        self._assert_audit_event_not_send(post_event, callbacks)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment_validate_admin_short_name(self, post_event, add_profile):
        self.set_permissions("mdm.add_depenrollment")
        request = self._create_dep_enrollment_request(
            admin_full_name=get_random_string(12), admin_short_name=None)
        add_profile.side_effect = Exception()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:dep_enrollments"),
                request
            )

        self.assertFalse(DEPEnrollment.objects.filter(name=request["name"]).exists())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"admin_short_name": ["Auto admin information incomplete"]}
        )

        self._assert_no_profil_added(add_profile)
        self._assert_audit_event_not_send(post_event, callbacks)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment_validate_await_device_configured(self, post_event, add_profile):
        self.set_permissions("mdm.add_depenrollment")
        request = self._create_dep_enrollment_request(
            admin_full_name=get_random_string(12),
            admin_short_name=get_random_string(12),
            await_device_configured=False)
        add_profile.side_effect = Exception()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:dep_enrollments"),
                request
            )

        self.assertFalse(DEPEnrollment.objects.filter(name=request["name"]).exists())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"await_device_configured": ["Required for the auto admin account setup"]}
        )

        self._assert_no_profil_added(add_profile)
        self._assert_audit_event_not_send(post_event, callbacks)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment_validate_skip_setup_items(self, post_event, add_profile):
        self.set_permissions("mdm.add_depenrollment")
        skip_setup_item = get_random_string(12)
        request = self._create_dep_enrollment_request(
            skip_setup_item=skip_setup_item)
        add_profile.side_effect = Exception()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:dep_enrollments"),
                request
            )

        self.assertFalse(DEPEnrollment.objects.filter(name=request["name"]).exists())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"skip_setup_items": [f"Unsupported items: {skip_setup_item}"]}
        )

        self._assert_no_profil_added(add_profile)
        self._assert_audit_event_not_send(post_event, callbacks)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment(self, post_event, add_profile):
        self.set_permissions("mdm.add_depenrollment")
        tag = self._given_tag()
        request = self._create_dep_enrollment_request(tag=tag)
        profile_uuid = uuid.uuid4()
        add_profile.return_value = {
            "devices": {},
            "profile_uuid": str(profile_uuid)
        }

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:dep_enrollments"),
                request
            )

        enrollment = DEPEnrollment.objects.get(name=request["name"])
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json(),
            self._dep_enrollment_to_dict(enrollment)
        )
        self.assertIsNotNone(enrollment.enrollment_secret.tags.get(id=tag.id))

        self._assert_audit_event_send(enrollment, post_event, callbacks, AuditEvent.Action.CREATED)

    # Update DEP enrollment

    def test_update_dep_enrollment_unauthorized(self):
        enrollment = force_dep_enrollment(self.mbu)
        response = self.put(
            reverse("mdm_api:dep_enrollment", args=(enrollment.id,)),
            {},
            include_token=False
        )
        self.assertEqual(response.status_code, 401)

    def test_update_dep_enrollment_permission_denied(self):
        enrollment = force_dep_enrollment(self.mbu)
        response = self.put(
            reverse("mdm_api:dep_enrollment", args=(enrollment.id,)),
            {}
        )
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_dep_enrollment_cannot_be_updated(self, post_event, add_profile):
        self.set_permissions("mdm.change_depenrollment")
        enrollment = force_dep_enrollment(self.mbu)
        add_profile.side_effect = Exception()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(
                reverse("mdm_api:dep_enrollment", args=(enrollment.id, )),
                self._create_dep_enrollment_request(is_mdm_removable=False)
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'is_mdm_removable': ["Can only be set to False if 'Is supervised' is set to True"]}
        )

        self._assert_no_profil_added(add_profile)
        self._assert_audit_event_not_send(post_event, callbacks)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_dep_enrollment(self, post_event, add_profile):
        self.set_permissions("mdm.change_depenrollment")
        enrollment = force_dep_enrollment(self.mbu)
        prev_value = enrollment.serialize_for_event()
        profile_uuid = uuid.uuid4()
        add_profile.return_value = {
            "devices": {},
            "profile_uuid": str(profile_uuid)
        }
        tag = self._given_tag()
        language = "en"

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(
                reverse("mdm_api:dep_enrollment", args=(enrollment.id,)),
                self._create_dep_enrollment_request(tag=tag, language=language)
            )

        enrollment.refresh_from_db()
        self.assertEqual(enrollment.uuid, profile_uuid)
        self.assertIsNotNone(enrollment.enrollment_secret.tags.get(id=tag.id))
        self.assertEqual(enrollment.language, language)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._dep_enrollment_to_dict(enrollment)
        )

        self._assert_audit_event_send(enrollment, post_event, callbacks, AuditEvent.Action.UPDATED, prev_value)

    # Delete DEP enrollment

    def test_delete_dep_enrollment_unauthorized(self):
        enrollment = force_dep_enrollment(self.mbu)

        response = self.delete(
            reverse("mdm_api:dep_enrollment", args=(enrollment.id,)),
            include_token=False
        )

        self.assertEqual(response.status_code, 401)

    def test_delete_dep_enrollment_permission_denied(self):
        enrollment = force_dep_enrollment(self.mbu)

        response = self.delete(reverse("mdm_api:dep_enrollment", args=(enrollment.id,)))

        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_dep_enrollment(self, post_event):
        self.set_permissions("mdm.delete_depenrollment")

        enrollment = force_dep_enrollment(self.mbu)
        prev_value = enrollment.serialize_for_event()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:dep_enrollment", args=(enrollment.id,)))

        self.assertFalse(DEPEnrollment.objects.filter(pk=enrollment.id).exists())
        self.assertEqual(response.status_code, 204)

        self._assert_audit_event_send(enrollment, post_event, callbacks, AuditEvent.Action.DELETED, prev_value)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_dep_enrollment_cannot_be_deleted(self, post_event):
        self.set_permissions("mdm.delete_depenrollment")

        enrollment = force_dep_enrollment(self.mbu)
        DEPEnrollmentSession.objects.create_from_dep_enrollment(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:dep_enrollment", args=(enrollment.id,)))

        self.assertTrue(DEPEnrollment.objects.filter(id=enrollment.id).exists())
        self.assertEqual(response.status_code, 400)

        self._assert_audit_event_not_send(post_event, callbacks)

    # List enrollment custom views

    def test_list_enrollment_custom_views_unauthorized(self):
        response = self.get(reverse("mdm_api:enrollment_custom_views"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_enrollment_custom_views_permission_denied(self):
        response = self.get(reverse("mdm_api:enrollment_custom_views"))
        self.assertEqual(response.status_code, 403)

    def test_list_enrollment_custom_views(self):
        self.set_permissions("mdm.view_enrollmentcustomview")
        view = force_enrollment_custom_view()
        response = self.get(reverse("mdm_api:enrollment_custom_views"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._enrollment_custom_view_to_list(view, 1))

    def test_list_enrollment_custom_view_by_name_no_results(self):
        self.set_permissions("mdm.view_enrollmentcustomview")
        response = self.get(reverse("mdm_api:enrollment_custom_views") + f"?name={get_random_string(12)}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), self._enrollment_custom_view_to_list())

    def test_list_enrollment_custom_view_ordering(self):
        self.set_permissions("mdm.view_enrollmentcustomview")

        view = self._given_ordered_entity_list(lambda: force_enrollment_custom_view())

        response = self.get(reverse("mdm_api:enrollment_custom_views")
                            + "?" + urlencode({"ordering": "-created_at",
                                               "limit": 1,
                                               "offset": 1}))
        self.assertEqual(EnrollmentCustomView.objects.count(), 3)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._enrollment_custom_view_to_list(
                view=view,
                count=3,
                next='http://testserver/api/mdm/enrollment_custom_views?limit=1&offset=2&ordering=-created_at',
                previous='http://testserver/api/mdm/enrollment_custom_views?limit=1&ordering=-created_at')
        )

    def test_list_enrollment_custom_view_by_name(self):
        self.set_permissions("mdm.view_enrollmentcustomview")
        view = force_enrollment_custom_view()
        response = self.get(reverse("mdm_api:enrollment_custom_views") + f"?name={view.name}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._enrollment_custom_view_to_list(view, 1))

    # Get enrollment custom view

    def test_get_enrollment_custom_views_unauthorized(self):
        view = force_enrollment_custom_view()
        response = self.get(
            reverse("mdm_api:enrollment_custom_view", args=(view.id, )),
            include_token=False
        )
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_custom_views_permission_denied(self):
        view = force_enrollment_custom_view()
        response = self.get(reverse("mdm_api:enrollment_custom_view", args=(view.id, )))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_custom_views(self):
        self.set_permissions("mdm.view_enrollmentcustomview")
        view = force_enrollment_custom_view()

        response = self.get(reverse("mdm_api:enrollment_custom_view", args=(view.id, )))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._enrollment_custom_view_to_dict(view)
        )

    # Create enrollment custom view

    def test_create_enrollment_custom_view_unauthorized(self):
        response = self.post(
                reverse("mdm_api:enrollment_custom_views"),
                {},
                include_token=False
            )
        self.assertEqual(response.status_code, 401)

    def test_create_enrollment_custom_view_permission_denied(self):
        response = self.post(
                reverse("mdm_api:enrollment_custom_views"),
                {}
            )
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_enrollment_custom_view(self, post_event):
        self.set_permissions("mdm.add_enrollmentcustomview")
        request = self._create_enrollment_custom_view_request()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:enrollment_custom_views"),
                request
            )

        view = EnrollmentCustomView.objects.get(name=request["name"])
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json(),
            self._enrollment_custom_view_to_dict(view)
        )
        self._assert_audit_event_send(view, post_event, callbacks, AuditEvent.Action.CREATED)

    # Update enrollment custom view

    def test_update_enrollment_custom_view_unauthorized(self):
        view = force_enrollment_custom_view()
        response = self.put(
                reverse("mdm_api:enrollment_custom_view", args=(view.id,)),
                {},
                include_token=False
            )
        self.assertEqual(response.status_code, 401)

    def test_update_enrollment_custom_view_permission_denied(self):
        view = force_enrollment_custom_view()
        response = self.put(
                reverse("mdm_api:enrollment_custom_view", args=(view.id,)),
                {}
            )
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_enrollment_custom_view(self, post_event):
        self.set_permissions("mdm.change_enrollmentcustomview")
        view = force_enrollment_custom_view()
        prev_value = view.serialize_for_event()
        request = self._create_enrollment_custom_view_request()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(
                reverse("mdm_api:enrollment_custom_view", args=(view.id,)),
                request
            )

        view.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._enrollment_custom_view_to_dict(view)
        )
        self._assert_audit_event_send(view, post_event, callbacks, AuditEvent.Action.UPDATED, prev_value)

    # Delete enrollment custom view

    def test_delete_enrollment_custom_views_unauthorized(self):
        view = force_enrollment_custom_view()

        response = self.delete(
            reverse("mdm_api:enrollment_custom_view", args=(view.id,)),
            include_token=False
        )

        self.assertEqual(response.status_code, 401)

    def test_delete_enrollment_custom_views_permission_denied(self):
        view = force_enrollment_custom_view()

        response = self.delete(reverse("mdm_api:enrollment_custom_view", args=(view.id,)))

        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_enrollment_custom_views(self, post_event):
        self.set_permissions("mdm.delete_enrollmentcustomview")

        view = force_enrollment_custom_view()
        prev_value = view.serialize_for_event()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:enrollment_custom_view", args=(view.id,)))

        self.assertFalse(EnrollmentCustomView.objects.filter(pk=view.id).exists())
        self.assertEqual(response.status_code, 204)

        self._assert_audit_event_send(view, post_event, callbacks, AuditEvent.Action.DELETED, prev_value)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_enrollment_custom_views_cannot_be_deleted(self, post_event):
        self.set_permissions("mdm.delete_enrollmentcustomview")

        view = force_enrollment_custom_view()
        enrollment = force_dep_enrollment(self.mbu)
        DEPEnrollmentCustomView.objects.create(
            dep_enrollment=enrollment,
            custom_view=view
        )

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:enrollment_custom_view", args=(view.id,)))

        self.assertTrue(EnrollmentCustomView.objects.filter(id=view.id).exists())
        self.assertEqual(response.status_code, 400)

        self._assert_audit_event_not_send(post_event, callbacks)

    # List DEP enrollment custom views

    def test_list_dep_enrollment_custom_views_unauthorized(self):
        response = self.get(reverse("mdm_api:dep_enrollment_custom_views"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_dep_enrollment_custom_views_permission_denied(self):
        response = self.get(reverse("mdm_api:dep_enrollment_custom_views"))
        self.assertEqual(response.status_code, 403)

    def test_list_dep_enrollment_custom_views(self):
        self.set_permissions("mdm.view_depenrollmentcustomview")
        view = self._given_dep_enrollment_custom_view()
        response = self.get(reverse("mdm_api:dep_enrollment_custom_views"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._dep_enrollment_custom_view_to_list(view, 1))

    def test_list_dep_enrollment_custom_view_ordering(self):
        self.set_permissions("mdm.view_depenrollmentcustomview")

        view = self._given_ordered_entity_list(lambda: self._given_dep_enrollment_custom_view())

        response = self.get(reverse("mdm_api:dep_enrollment_custom_views")
                            + "?" + urlencode({"ordering": "-created_at",
                                               "limit": 1,
                                               "offset": 1}))
        self.assertEqual(DEPEnrollmentCustomView.objects.count(), 3)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._dep_enrollment_custom_view_to_list(
                view=view,
                count=3,
                next='http://testserver/api/mdm/dep_enrollment_custom_views?limit=1&offset=2&ordering=-created_at',
                previous='http://testserver/api/mdm/dep_enrollment_custom_views?limit=1&ordering=-created_at')
        )

    # Get DEP enrollment custom view

    def test_get_dep_enrollment_custom_views_unauthorized(self):
        view = self._given_dep_enrollment_custom_view()
        response = self.get(
            reverse("mdm_api:dep_enrollment_custom_view", args=(view.id, )),
            include_token=False
        )
        self.assertEqual(response.status_code, 401)

    def test_get_dep_enrollment_custom_views_permission_denied(self):
        view = self._given_dep_enrollment_custom_view()
        response = self.get(reverse("mdm_api:dep_enrollment_custom_view", args=(view.id, )))
        self.assertEqual(response.status_code, 403)

    def test_get_dep_enrollment_custom_views(self):
        self.set_permissions("mdm.view_depenrollmentcustomview")
        view = self._given_dep_enrollment_custom_view()

        response = self.get(reverse("mdm_api:dep_enrollment_custom_view", args=(view.id, )))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._dep_enrollment_custom_view_to_dict(view)
        )

    # Create DEP enrollment custom view

    def test_create_edep_nrollment_custom_view_unauthorized(self):
        response = self.post(
                reverse("mdm_api:dep_enrollment_custom_views"),
                {},
                include_token=False
            )
        self.assertEqual(response.status_code, 401)

    def test_create_dep_enrollment_custom_view_permission_denied(self):
        response = self.post(
                reverse("mdm_api:dep_enrollment_custom_views"),
                {}
            )
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment_custom_view(self, post_event):
        self.set_permissions("mdm.add_depenrollmentcustomview")
        view = force_enrollment_custom_view()
        request = self._create_dep_enrollment_custom_view_request(custom_view=view)

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:dep_enrollment_custom_views"),
                request
            )

        view = DEPEnrollmentCustomView.objects.get(custom_view__id=view.id)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json(),
            self._dep_enrollment_custom_view_to_dict(view)
        )
        self._assert_audit_event_send(view, post_event, callbacks, AuditEvent.Action.CREATED)

    # Update DEP enrollment custom view

    def test_update_dep_enrollment_custom_view_unauthorized(self):
        view = self._given_dep_enrollment_custom_view()
        response = self.put(
                reverse("mdm_api:dep_enrollment_custom_view", args=(view.id,)),
                {},
                include_token=False
            )
        self.assertEqual(response.status_code, 401)

    def test_update_dep_enrollment_custom_view_permission_denied(self):
        view = self._given_dep_enrollment_custom_view()
        response = self.put(
                reverse("mdm_api:dep_enrollment_custom_view", args=(view.id,)),
                {}
            )
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_dep_enrollment_custom_view(self, post_event):
        self.set_permissions("mdm.change_depenrollmentcustomview")
        view = self._given_dep_enrollment_custom_view()
        prev_value = view.serialize_for_event()
        request = self._create_dep_enrollment_custom_view_request()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(
                reverse("mdm_api:dep_enrollment_custom_view", args=(view.id,)),
                request
            )

        view.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._dep_enrollment_custom_view_to_dict(view)
        )
        self._assert_audit_event_send(view, post_event, callbacks, AuditEvent.Action.UPDATED, prev_value)

    # Delete DEP enrollment custom view

    def test_delete_dep_enrollment_custom_views_unauthorized(self):
        view = self._given_dep_enrollment_custom_view()
        response = self.delete(
            reverse("mdm_api:dep_enrollment_custom_view", args=(view.id,)),
            include_token=False
        )

        self.assertEqual(response.status_code, 401)

    def test_delete_dep_enrollment_custom_views_permission_denied(self):
        view = self._given_dep_enrollment_custom_view()

        response = self.delete(reverse("mdm_api:dep_enrollment_custom_view", args=(view.id,)))

        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_dep_enrollment_custom_views(self, post_event):
        self.set_permissions("mdm.delete_depenrollmentcustomview")

        view = self._given_dep_enrollment_custom_view()
        prev_value = view.serialize_for_event()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:dep_enrollment_custom_view", args=(view.id,)))

        self.assertFalse(EnrollmentCustomView.objects.filter(pk=view.id).exists())
        self.assertEqual(response.status_code, 204)

        self._assert_audit_event_send(view, post_event, callbacks, AuditEvent.Action.DELETED, prev_value)
