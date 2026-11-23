from unittest.mock import PropertyMock, patch

from django.http import HttpResponse, HttpResponseNotModified
from django.template.response import SimpleTemplateResponse
from django.test import RequestFactory, TestCase
from django.urls import reverse

from django.contrib.auth.models import AnonymousUser, Group
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from pbac.engine import engine
from pbac.types import SERVICE_ACCOUNT, USER
from tests.mdm.utils import force_dep_enrollment, force_ota_enrollment, force_user_enrollment
from tests.monolith.utils import force_enrollment as force_monolith_enrollment
from tests.munki.utils import force_enrollment as force_munki_enrollment
from tests.osquery.utils import force_enrollment as force_osquery_enrollment
from tests.santa.utils import force_configuration as force_santa_configuration
from tests.turbo.utils import force_enrollment as force_turbo_enrollment
from tests.zentral_test_utils.enrollment_secret_case import EnrollmentSecretCase
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from zentral.contrib.inventory.enrollment_secrets import enrollment_pks_with_secret, enrollment_secret_download
from zentral.contrib.inventory.events import EnrollmentSecretViewedEvent, post_enrollment_secret_viewed_event
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from zentral.contrib.mdm.dep_client import DEPClientError
from zentral.contrib.santa.models import Enrollment as SantaEnrollment
from zentral.contrib.santa.pbac import ViewEnrollmentSecretRequest as ViewSantaEnrollmentSecretRequest
from zentral.core.events.base import linked_objects_key
from zentral.core.stores.conf import stores
from zentral.utils.provisioning import provision


# the actions


class EnrollmentSecretActionsTestCase(TestCase):
    actions = (
        ("Santa", "viewEnrollmentSecret", "Enrollment"),
        ("Osquery", "viewEnrollmentSecret", "Enrollment"),
        ("Munki", "viewEnrollmentSecret", "Enrollment"),
        ("Monolith", "viewEnrollmentSecret", "Enrollment"),
        ("Turbo", "viewEnrollmentSecret", "Enrollment"),
        ("MDM", "viewOTAEnrollmentSecret", "OTAEnrollment"),
        ("MDM", "viewDEPEnrollmentSecret", "DEPEnrollment"),
        ("MDM", "viewUserEnrollmentSecret", "UserEnrollment"),
    )

    def test_actions(self):
        for namespace, action_id, resource_name in self.actions:
            action = engine.get_action(action_id, engine.get_namespace(namespace))
            self.assertEqual(action.applies_to.principals, (USER, SERVICE_ACCOUNT))
            self.assertEqual([resource_type.qualified_name for resource_type in action.applies_to.resources],
                             [f"{namespace}::{resource_name}"])
            self.assertEqual([parent.qualified_name for parent in action.applies_to.resources[0].parents],
                             ["Inventory::MetaBusinessUnit"])
            self.assertIsNone(action.applies_to.context)
            # user level, not in the viewer groups
            self.assertEqual(
                [str(group) for group in action.parents],
                [f'{namespace}::Action::"AdminActions"', 'Action::"GlobalAdminActions"',
                 f'{namespace}::Action::"UserActions"', 'Action::"GlobalUserActions"']
            )

    def test_no_legacy_permission(self):
        for namespace, action_id, _ in self.actions:
            action = engine.get_action(action_id, engine.get_namespace(namespace))
            self.assertNotIn(action, engine.legacy_perm_actions.values())


# the modules


class SantaEnrollmentSecretTestCase(EnrollmentSecretCase, TestCase, LoginCase, RequestCase):
    es_parent_field = "configuration"
    es_namespace = "Santa"
    es_view_permission = "santa.view_enrollment"
    es_page_permissions = ("santa.view_configuration",)

    def _get_url_namespace(self):
        return "santa"

    def es_force_enrollment(self, mbu):
        return SantaEnrollment.objects.create(configuration=force_santa_configuration(),
                                              secret=EnrollmentSecret.objects.create(meta_business_unit=mbu))

    def es_list_url(self):
        return reverse("santa_api:enrollments")

    def es_detail_url(self, enrollment):
        return reverse("santa_api:enrollment", args=(enrollment.pk,))

    def es_download_urls(self, enrollment):
        return [reverse("santa_api:enrollment_plist", args=(enrollment.pk,)),
                reverse("santa_api:enrollment_configuration_profile", args=(enrollment.pk,))]

    def es_page(self, enrollment):
        return (reverse("santa:configuration", args=(enrollment.configuration.pk,)),
                self.es_download_urls(enrollment))


class OsqueryEnrollmentSecretTestCase(EnrollmentSecretCase, TestCase, LoginCase, RequestCase):
    es_parent_field = "configuration"
    es_namespace = "Osquery"
    es_view_permission = "osquery.view_enrollment"
    es_page_permissions = ("osquery.view_configuration",)

    def _get_url_namespace(self):
        return "osquery"

    def es_force_enrollment(self, mbu):
        return force_osquery_enrollment(meta_business_unit=mbu)

    def es_list_url(self):
        return reverse("osquery_api:enrollments")

    def es_detail_url(self, enrollment):
        return reverse("osquery_api:enrollment", args=(enrollment.pk,))

    def es_download_urls(self, enrollment):
        return [reverse(f"osquery_api:enrollment_{name}", args=(enrollment.pk,))
                for name in ("package", "script", "powershell_script")]

    def es_page(self, enrollment):
        return (reverse("osquery:configuration", args=(enrollment.configuration.pk,)),
                self.es_download_urls(enrollment))


class MunkiEnrollmentSecretTestCase(EnrollmentSecretCase, TestCase, LoginCase, RequestCase):
    es_parent_field = "configuration"
    es_namespace = "Munki"
    es_view_permission = "munki.view_enrollment"
    es_page_permissions = ("munki.view_configuration",)

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        # the configuration page reads the store of the console
        provision()
        stores._load(force=True)

    def _get_url_namespace(self):
        return "munki"

    def es_force_enrollment(self, mbu):
        return force_munki_enrollment(meta_business_unit=mbu)

    def es_list_url(self):
        return reverse("munki_api:enrollments")

    def es_detail_url(self, enrollment):
        return reverse("munki_api:enrollment", args=(enrollment.pk,))

    def es_download_urls(self, enrollment):
        return [reverse("munki_api:enrollment_package", args=(enrollment.pk,))]

    def es_page(self, enrollment):
        return (reverse("munki:configuration", args=(enrollment.configuration.pk,)),
                self.es_download_urls(enrollment))


class MonolithEnrollmentSecretTestCase(EnrollmentSecretCase, TestCase, LoginCase, RequestCase):
    es_parent_field = "manifest"
    es_namespace = "Monolith"
    es_view_permission = "monolith.view_enrollment"
    es_page_permissions = ("monolith.view_manifest",)

    def _get_url_namespace(self):
        return "monolith"

    def es_force_enrollment(self, mbu):
        return force_monolith_enrollment(mbu=mbu)[0]

    def es_list_url(self):
        return reverse("monolith_api:enrollments")

    def es_detail_url(self, enrollment):
        return reverse("monolith_api:enrollment", args=(enrollment.pk,))

    def es_download_urls(self, enrollment):
        return [reverse("monolith_api:enrollment_plist", args=(enrollment.pk,)),
                reverse("monolith_api:enrollment_configuration_profile", args=(enrollment.pk,))]

    def es_page(self, enrollment):
        return (reverse("monolith:manifest", args=(enrollment.manifest.pk,)),
                self.es_download_urls(enrollment))


class TurboEnrollmentSecretTestCase(EnrollmentSecretCase, TestCase, LoginCase, RequestCase):
    es_parent_field = "configuration"
    es_namespace = "Turbo"
    es_view_permission = "turbo.view_enrollment"
    es_page_permissions = ("turbo.view_configuration",)

    def _get_url_namespace(self):
        return "turbo"

    def es_force_enrollment(self, mbu):
        return force_turbo_enrollment(meta_business_unit=mbu)

    def es_list_url(self):
        return reverse("turbo_api:enrollments")

    def es_detail_url(self, enrollment):
        return reverse("turbo_api:enrollment", args=(enrollment.pk,))

    def es_download_urls(self, enrollment):
        return [reverse("turbo_api:enrollment_plist", args=(enrollment.pk,)),
                reverse("turbo_api:enrollment_configuration_profile", args=(enrollment.pk,))]

    def es_page(self, enrollment):
        return (reverse("turbo:configuration", args=(enrollment.configuration.pk,)),
                self.es_download_urls(enrollment))


class MDMOTAEnrollmentSecretTestCase(EnrollmentSecretCase, TestCase, LoginCase, RequestCase):
    es_namespace = "MDM"
    es_action = "viewOTAEnrollmentSecret"
    es_resource_name = "OTAEnrollment"
    es_view_permission = "mdm.view_otaenrollment"
    es_secret_key = "enrollment_secret"

    def _get_url_namespace(self):
        return "mdm"

    def es_force_enrollment(self, mbu):
        return force_ota_enrollment(mbu=mbu)

    def es_list_url(self):
        return reverse("mdm_api:ota_enrollments")

    def es_detail_url(self, enrollment):
        return reverse("mdm_api:ota_enrollment", args=(enrollment.pk,))

    def es_page(self, enrollment):
        return (reverse("mdm:ota_enrollment", args=(enrollment.pk,)),
                [reverse("mdm:download_profile_service_payload", args=(enrollment.pk,))])

    # the profile download of the console

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_es_profile_download(self, post_event):
        enrollment = self.es_force_enrollment(self.mbu)
        other_enrollment = self.es_force_enrollment(self.other_mbu)
        url = reverse("mdm:download_profile_service_payload", args=(enrollment.pk,))
        self.client.force_login(self.user)
        # the action alone: the view permission opens the download
        self.es_set_policies(("permit", "resource"))
        self.assertEqual(self.client.get(url).status_code, 403)
        # the view permission alone: the profile is the secret
        self.es_set_policies(permissions=(self.es_view_permission,))
        with self.assertLogs("zentral.pbac.utils", level="WARNING"):
            self.assertEqual(self.client.get(url).status_code, 403)
        self.es_set_policies(("permit", self.es_in_mbu(self.mbu)), permissions=(self.es_view_permission,))
        self.assertEqual(self.client.get(url).status_code, 200)
        with self.assertLogs("zentral.pbac.utils", level="WARNING"):
            response = self.client.get(reverse("mdm:download_profile_service_payload", args=(other_enrollment.pk,)))
        self.assertEqual(response.status_code, 403)
        events = self.es_events(post_event)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].payload["where"], "ota_profile_download")


class MDMDEPEnrollmentSecretTestCase(EnrollmentSecretCase, TestCase, LoginCase, RequestCase):
    es_namespace = "MDM"
    es_action = "viewDEPEnrollmentSecret"
    es_resource_name = "DEPEnrollment"
    es_view_permission = "mdm.view_depenrollment"
    es_secret_key = "enrollment_secret"

    def _get_url_namespace(self):
        return "mdm"

    def es_force_enrollment(self, mbu):
        return force_dep_enrollment(mbu)

    def es_list_url(self):
        return reverse("mdm_api:dep_enrollments")

    def es_detail_url(self, enrollment):
        return reverse("mdm_api:dep_enrollment", args=(enrollment.pk,))

    def es_page(self, enrollment):
        return (reverse("mdm:dep_enrollment", args=(enrollment.pk,)),
                [reverse("mdm:check_dep_enrollment", args=(enrollment.pk,))])

    # the check page prints the profile that Apple holds, with the secret in its URLs

    @patch("zentral.contrib.mdm.views.dep_enrollments.DEPClient.from_dep_virtual_server")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_es_check_page(self, post_event, from_dep_virtual_server):
        from_dep_virtual_server.return_value.get_profile.return_value = {"url": "https://zentral"}
        enrollment = self.es_force_enrollment(self.mbu)
        other_enrollment = self.es_force_enrollment(self.other_mbu)
        url = reverse("mdm:check_dep_enrollment", args=(enrollment.pk,))
        self.client.force_login(self.user)
        # the action alone: the view permission opens the page
        self.es_set_policies(("permit", "resource"))
        self.assertEqual(self.client.get(url).status_code, 403)
        # the view permission alone: the page is the secret
        self.es_set_policies(permissions=(self.es_view_permission,))
        with self.assertLogs("zentral.pbac.utils", level="WARNING"):
            self.assertEqual(self.client.get(url).status_code, 403)
        self.es_set_policies(("permit", self.es_in_mbu(self.mbu)), permissions=(self.es_view_permission,))
        self.assertEqual(self.client.get(url).status_code, 200)
        with self.assertLogs("zentral.pbac.utils", level="WARNING"):
            response = self.client.get(reverse("mdm:check_dep_enrollment", args=(other_enrollment.pk,)))
        self.assertEqual(response.status_code, 403)
        events = self.es_events(post_event)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].payload["where"], "dep_check_page")

    @patch("zentral.contrib.mdm.views.dep_enrollments.DEPClient.from_dep_virtual_server")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_es_check_page_fetch_error(self, post_event, from_dep_virtual_server):
        # no profile, no secret on the page: no event
        from_dep_virtual_server.return_value.get_profile.side_effect = DEPClientError("yolo")
        enrollment = self.es_force_enrollment(self.mbu)
        self.client.force_login(self.user)
        self.es_set_policies(("permit", "resource"), permissions=(self.es_view_permission,))
        with self.assertRaises(DEPClientError):
            self.client.get(reverse("mdm:check_dep_enrollment", args=(enrollment.pk,)))
        self.assertEqual(self.es_events(post_event), [])

    @patch("zentral.contrib.mdm.views.dep_enrollments.DEPClient.from_dep_virtual_server")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_es_check_page_render_error(self, post_event, from_dep_virtual_server):
        # the page is not rendered: no event
        from_dep_virtual_server.return_value.get_profile.return_value = {"url": "https://zentral"}
        enrollment = self.es_force_enrollment(self.mbu)
        self.client.force_login(self.user)
        self.es_set_policies(("permit", "resource"), permissions=(self.es_view_permission,))
        with patch.object(SimpleTemplateResponse, "rendered_content", new_callable=PropertyMock,
                          side_effect=RuntimeError("render failed")):
            with self.assertRaises(RuntimeError):
                self.client.get(reverse("mdm:check_dep_enrollment", args=(enrollment.pk,)))
        self.assertEqual(self.es_events(post_event), [])


class MDMUserEnrollmentSecretTestCase(TestCase, LoginCase):
    """The user enrollment has no API. Its page shows the service discovery URL, which holds the secret."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.io",
                                            get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.other_mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm"

    def _set_policies(self, *statements, permissions=()):
        self.set_permissions(*permissions)
        source = "".join(f'{effect} (principal in Role::"{self.group.pk}", '
                         f'action == MDM::Action::"viewUserEnrollmentSecret", {scope});\n'
                         for effect, scope in statements)
        Policy.objects.filter(name="Tests enrollment secrets").delete()
        if source:
            Policy.objects.create(name="Tests enrollment secrets", source=source)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_page(self, post_event):
        enrollment = force_user_enrollment(self.mbu)
        other_enrollment = force_user_enrollment(self.other_mbu)
        url = reverse("mdm:user_enrollment", args=(enrollment.pk,))
        secret = enrollment.enrollment_secret.secret
        self.client.force_login(self.user)
        # the action alone: the view permission opens the page
        self._set_policies(("permit", "resource"))
        self.assertEqual(self.client.get(url).status_code, 403)
        # the view permission: the page, without the URL, and nothing logged
        self._set_policies(permissions=("mdm.view_userenrollment",))
        with self.assertNoLogs("zentral.pbac.utils", level="WARNING"):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, secret)
        # the view permission and the action in one business unit: the URL
        self._set_policies(("permit", f'resource in Inventory::MetaBusinessUnit::"{self.mbu.pk}"'),
                           permissions=("mdm.view_userenrollment",))
        response = self.client.get(url)
        self.assertContains(response, secret)
        response = self.client.get(reverse("mdm:user_enrollment", args=(other_enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, other_enrollment.enrollment_secret.secret)
        events = [call.args[0] for call in post_event.call_args_list
                  if isinstance(call.args[0], EnrollmentSecretViewedEvent)]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].payload["where"], "user_enrollment_page")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_page_without_realm(self, post_event):
        # no realm, no service discovery URL: the secret is not on the page, no event
        enrollment = force_user_enrollment(self.mbu)
        enrollment.realm = None
        enrollment.save()
        self.client.force_login(self.user)
        self._set_policies(("permit", "resource"), permissions=("mdm.view_userenrollment",))
        response = self.client.get(reverse("mdm:user_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, enrollment.enrollment_secret.secret)
        self.assertEqual([call.args[0] for call in post_event.call_args_list
                          if isinstance(call.args[0], EnrollmentSecretViewedEvent)], [])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_page_render_error(self, post_event):
        # the page is not rendered: no event
        enrollment = force_user_enrollment(self.mbu)
        self.client.force_login(self.user)
        self._set_policies(("permit", "resource"), permissions=("mdm.view_userenrollment",))
        with patch.object(SimpleTemplateResponse, "rendered_content", new_callable=PropertyMock,
                          side_effect=RuntimeError("render failed")):
            with self.assertRaises(RuntimeError):
                self.client.get(reverse("mdm:user_enrollment", args=(enrollment.pk,)))
        self.assertEqual([call.args[0] for call in post_event.call_args_list
                          if isinstance(call.args[0], EnrollmentSecretViewedEvent)], [])


# the rows of a page


class EnrollmentSecretRowsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.io",
                                            get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.enrollment, cls.other_enrollment = (
            SantaEnrollment.objects.create(configuration=force_santa_configuration(),
                                           secret=EnrollmentSecret.objects.create(meta_business_unit=mbu))
            for mbu in (cls.mbu, MetaBusinessUnit.objects.create(name=get_random_string(12)))
        )

    def test_rows_sql_and_decisions(self):
        # `has` is not in the SQL subset, so each enrollment gets its own decision: the same rows
        in_mbu = f'resource in Inventory::MetaBusinessUnit::"{self.mbu.pk}"'
        for scope, when, decided_rows in ((in_mbu, "", False),
                                          ("resource", f" when {{ {in_mbu} && !(resource has yolo) }}", True)):
            Policy.objects.update_or_create(
                name="Tests enrollment secret rows",
                defaults={"source": (f'permit (principal in Role::"{self.group.pk}", '
                                     f'action == Santa::Action::"viewEnrollmentSecret", {scope}){when};\n')}
            )
            with patch.object(ViewSantaEnrollmentSecretRequest, "requests_for_rows",
                              wraps=ViewSantaEnrollmentSecretRequest.requests_for_rows) as requests_for_rows:
                pks = enrollment_pks_with_secret(
                    User.objects.get(pk=self.user.pk), ViewSantaEnrollmentSecretRequest,
                    SantaEnrollment.objects.filter(pk__in=(self.enrollment.pk, self.other_enrollment.pk))
                )
            self.assertEqual(pks, {self.enrollment.pk})
            self.assertEqual(requests_for_rows.called, decided_rows)


# the helpers


class EnrollmentSecretHelpersTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.secret = EnrollmentSecret.objects.create(
            meta_business_unit=MetaBusinessUnit.objects.create(name=get_random_string(12))
        )

    def test_serializer_without_decision(self):
        # a serializer outside the views that decide the secret returns none
        self.assertIsNone(EnrollmentSecretSerializer(self.secret).data["secret"])

    def test_serializer_decided(self):
        data = EnrollmentSecretSerializer(self.secret, context={"enrollment_secret_pks": {self.secret.pk}}).data
        self.assertEqual(data["secret"], self.secret.secret)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_event_no_enrollments(self, post_event):
        request = RequestFactory().get("/")
        request.user = AnonymousUser()
        post_enrollment_secret_viewed_event(request, [], "secret", "api_list")
        post_event.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_event_linked_objects(self, post_event):
        # one link for each enrollment, and one for each business unit, in the order of the response
        mbu = self.secret.meta_business_unit
        other_mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        enrollments = [force_munki_enrollment(meta_business_unit=mbu),
                       force_munki_enrollment(meta_business_unit=other_mbu),
                       force_munki_enrollment(meta_business_unit=mbu)]
        request = RequestFactory().get("/")
        request.user = AnonymousUser()
        post_enrollment_secret_viewed_event(request, enrollments, "secret", "api_list")
        event = post_event.call_args.args[0]
        self.assertEqual(event.metadata.objects,
                         {linked_objects_key(enrollments[0]): [(enrollment.pk,) for enrollment in enrollments],
                          linked_objects_key(MetaBusinessUnit): [(mbu.pk,), (other_mbu.pk,)]})
        self.assertEqual([enrollment["pk"] for enrollment in event.payload["enrollments"]],
                         [enrollment.pk for enrollment in enrollments])

    def _download(self, build_response):
        request = RequestFactory().get("/")
        request.resolver_match = type("ResolverMatch", (), {"url_name": "enrollment_plist"})()
        enrollment = type("Enrollment", (), {"secret": self.secret})()
        with patch("zentral.contrib.inventory.enrollment_secrets.check_enrollment_secret") as check, \
             patch("zentral.contrib.inventory.enrollment_secrets.post_enrollment_secret_viewed_event") as post:
            try:
                return enrollment_secret_download(request, type("R", (), {"secret_field": "secret"}), enrollment,
                                                  build_response), check, post
            except RuntimeError:
                return None, check, post

    def test_download_event(self):
        response, check, post = self._download(lambda: HttpResponse(b"yolo"))
        self.assertEqual(response.status_code, 200)
        check.assert_called_once()
        post.assert_called_once()
        self.assertEqual(post.call_args.args[3], "download:enrollment_plist")

    def test_download_not_modified_no_event(self):
        response, check, post = self._download(lambda: HttpResponseNotModified())
        self.assertEqual(response.status_code, 304)
        check.assert_called_once()
        post.assert_not_called()

    def test_download_failed_build_no_event(self):
        def build_response():
            raise RuntimeError("build failed")
        response, check, post = self._download(build_response)
        self.assertIsNone(response)
        check.assert_called_once()
        post.assert_not_called()
