from abc import ABC, abstractmethod
import tempfile
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils.crypto import get_random_string

from accounts.models import APIToken, Policy, User
from pbac.engine import engine
from zentral.contrib.inventory.events import EnrollmentSecretViewedEvent
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.core.events.base import linked_objects_key


class EnrollmentSecretCase(ABC):
    """The rule 15 matrix of the secret of an enrollment, for each module.

    The view permission opens the enrollment. The secret action decides only its secret.

    The class also inherits from TestCase, LoginCase and RequestCase.
    """
    # the namespace and the name of the action, the view permission of the model, the key of the secret object in
    # the enrollment of the API
    es_namespace = None
    es_action = "viewEnrollmentSecret"
    es_resource_name = "Enrollment"
    es_view_permission = None
    es_secret_key = "secret"
    # the permissions that open the console page with the download links, if there is one
    es_page_permissions = ()

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.io",
                                            get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.service_account = User.objects.create(username=get_random_string(12),
                                                  email=f"{get_random_string(12)}@zentral.io",
                                                  is_service_account=True)
        cls.service_account.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.other_mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))

    # LoginCase and RequestCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_api_key(self):
        return self.api_key

    # the module

    @abstractmethod
    def es_force_enrollment(self, mbu):
        """An enrollment with a secret in the business unit."""

    @abstractmethod
    def es_list_url(self):
        pass

    @abstractmethod
    def es_detail_url(self, enrollment):
        pass

    def es_download_urls(self, enrollment):
        """The URLs of the downloads that hold the secret."""
        return []

    def es_page(self, enrollment):
        """The console page that shows the download links, and the links. None if there is no page."""
        return None

    # the body of a create of an enrollment, with the parent of the given one. None if the case does not write.
    es_parent_field = None

    def es_write_payload(self, enrollment, mbu):
        if self.es_parent_field is None:
            return None
        return {self.es_parent_field: getattr(enrollment, self.es_parent_field).pk,
                "secret": {"meta_business_unit": mbu.pk, "tags": []}}

    @property
    def es_app_label(self):
        return self.es_view_permission.split(".")[0]

    # utility methods

    def es_set_policies(self, *statements, permissions=()):
        self.set_permissions(*permissions)
        role = f'Role::"{self.group.pk}"'
        action = f'{self.es_namespace}::Action::"{self.es_action}"'
        source = "".join(f"{effect} (principal in {role}, action == {action}, {scope});\n"
                         for effect, scope in statements)
        if source:
            Policy.objects.update_or_create(name="Tests enrollment secrets", defaults={"source": source})
        else:
            Policy.objects.filter(name="Tests enrollment secrets").delete()

    def es_in_mbu(self, mbu):
        return f'resource in Inventory::MetaBusinessUnit::"{mbu.pk}"'

    def es_secret(self, enrollment_json):
        return enrollment_json[self.es_secret_key]["secret"]

    def es_stored_secret(self, enrollment):
        return getattr(enrollment, "secret" if self.es_secret_key == "secret" else self.es_secret_key).secret

    def es_rows(self, response):
        data = response.json()
        rows = data["results"] if isinstance(data, dict) else data
        return {row["id"]: row for row in rows}

    def es_unknown_pk(self, enrollment):
        return type(enrollment).objects.order_by("-pk").first().pk + 1000

    def es_events(self, post_event):
        return [call.args[0] for call in post_event.call_args_list
                if isinstance(call.args[0], EnrollmentSecretViewedEvent)]

    def es_event_pks(self, event):
        return [enrollment["pk"] for enrollment in event.payload["enrollments"]]

    # list

    def test_es_list_unauthorized(self):
        self.assertEqual(self.get(self.es_list_url(), include_token=False).status_code, 401)

    def test_es_list_the_action_alone(self):
        # the action gives the secret only: the view permission opens the list
        self.es_force_enrollment(self.mbu)
        self.es_set_policies(("permit", "resource"))
        self.assertEqual(self.get(self.es_list_url()).status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_es_list_view_permission_only(self, post_event):
        enrollment = self.es_force_enrollment(self.mbu)
        self.es_set_policies(permissions=(self.es_view_permission,))
        # a secret left out of a response is a filter: no log
        with self.assertNoLogs("zentral.pbac.utils", level="WARNING"):
            response = self.get(self.es_list_url())
        self.assertEqual(response.status_code, 200)
        rows = self.es_rows(response)
        self.assertIsNone(self.es_secret(rows[enrollment.pk]))
        self.assertEqual(self.es_events(post_event), [])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_es_list_view_permission_and_the_action(self, post_event):
        enrollment = self.es_force_enrollment(self.mbu)
        self.es_set_policies(("permit", "resource"), permissions=(self.es_view_permission,))
        response = self.get(self.es_list_url())
        self.assertEqual(response.status_code, 200)
        rows = self.es_rows(response)
        self.assertEqual(self.es_secret(rows[enrollment.pk]), self.es_stored_secret(enrollment))
        # one event for the response
        events = self.es_events(post_event)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].payload["where"], "api_list")
        self.assertIn({"module": self.es_app_label, "model": type(enrollment)._meta.model_name, "pk": enrollment.pk,
                       "meta_business_unit": {"pk": self.mbu.pk}},
                      events[0].payload["enrollments"])
        self.assertEqual(events[0].metadata.request.user.id, self.service_account.pk)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_es_list_forbid_mbu(self, post_event):
        enrollment = self.es_force_enrollment(self.mbu)
        other_enrollment = self.es_force_enrollment(self.other_mbu)
        self.es_set_policies(("permit", "resource"), ("forbid", self.es_in_mbu(self.other_mbu)),
                             permissions=(self.es_view_permission,))
        with self.assertNoLogs("zentral.pbac.utils", level="WARNING"):
            response = self.get(self.es_list_url())
        rows = self.es_rows(response)
        # each row of the view permission, with or without its secret
        self.assertEqual(self.es_secret(rows[enrollment.pk]), self.es_stored_secret(enrollment))
        self.assertIsNone(self.es_secret(rows[other_enrollment.pk]))
        events = self.es_events(post_event)
        self.assertEqual(len(events), 1)
        self.assertEqual(set(self.es_event_pks(events[0])) & {enrollment.pk, other_enrollment.pk}, {enrollment.pk})

    def test_es_list_one_batch(self):
        self.es_force_enrollment(self.mbu)
        self.es_force_enrollment(self.other_mbu)
        self.es_set_policies(("permit", "resource"), permissions=(self.es_view_permission,))
        with patch.object(engine, "authorize_requests", wraps=engine.authorize_requests) as authorize_requests:
            response = self.get(self.es_list_url())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(authorize_requests.call_count, 1)

    def test_es_list_same_number_of_queries(self):
        self.es_set_policies(("permit", self.es_in_mbu(self.mbu)), permissions=(self.es_view_permission,))
        self.es_force_enrollment(self.mbu)
        self.es_force_enrollment(self.other_mbu)
        self.get(self.es_list_url())
        with CaptureQueriesContext(connection) as ctx:
            self.get(self.es_list_url())
        for mbu in (self.mbu, self.other_mbu, self.mbu):
            self.es_force_enrollment(mbu)
        with self.assertNumQueries(len(ctx)):
            self.get(self.es_list_url())

    # detail

    def test_es_detail_unauthorized(self):
        enrollment = self.es_force_enrollment(self.mbu)
        self.assertEqual(self.get(self.es_detail_url(enrollment), include_token=False).status_code, 401)

    def test_es_detail_the_action_alone(self):
        enrollment = self.es_force_enrollment(self.mbu)
        self.es_set_policies(("permit", "resource"))
        self.assertEqual(self.get(self.es_detail_url(enrollment)).status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_es_detail_view_permission_only(self, post_event):
        enrollment = self.es_force_enrollment(self.mbu)
        self.es_set_policies(permissions=(self.es_view_permission,))
        with self.assertNoLogs("zentral.pbac.utils", level="WARNING"):
            response = self.get(self.es_detail_url(enrollment))
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.es_secret(response.json()))
        self.assertEqual(self.es_events(post_event), [])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_es_detail_view_permission_and_the_action(self, post_event):
        enrollment = self.es_force_enrollment(self.mbu)
        other_enrollment = self.es_force_enrollment(self.other_mbu)
        self.es_set_policies(("permit", "resource"), ("forbid", self.es_in_mbu(self.other_mbu)),
                             permissions=(self.es_view_permission,))
        response = self.get(self.es_detail_url(enrollment))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.es_secret(response.json()), self.es_stored_secret(enrollment))
        with self.assertNoLogs("zentral.pbac.utils", level="WARNING"):
            response = self.get(self.es_detail_url(other_enrollment))
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.es_secret(response.json()))
        events = self.es_events(post_event)
        self.assertEqual(len(events), 1)
        self.assertEqual(self.es_event_pks(events[0]), [enrollment.pk])
        self.assertEqual(events[0].payload["where"], "api_detail")
        # the events of the enrollment and of its business unit show the read
        self.assertEqual(events[0].metadata.objects,
                         {linked_objects_key(enrollment): [(enrollment.pk,)],
                          linked_objects_key(MetaBusinessUnit): [(self.mbu.pk,)]})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_es_read_failed_render_no_event(self, post_event):
        # the event is sent once the response is rendered
        enrollment = self.es_force_enrollment(self.mbu)
        self.es_set_policies(("permit", "resource"), permissions=(self.es_view_permission,))
        with patch("rest_framework.renderers.JSONRenderer.render", side_effect=RuntimeError("render failed")):
            for url in (self.es_list_url(), self.es_detail_url(enrollment)):
                with self.assertRaises(RuntimeError):
                    self.get(url)
        self.assertEqual(self.es_events(post_event), [])

    # writes: the response decides the secret too

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_es_create_response(self, post_event):
        enrollment = self.es_force_enrollment(self.mbu)
        payload = self.es_write_payload(enrollment, self.mbu)
        if payload is None:
            self.skipTest("no write")
        add_permission = f"{self.es_app_label}.add_enrollment"
        self.es_set_policies(("permit", "resource"), ("forbid", self.es_in_mbu(self.mbu)),
                             permissions=(add_permission,))
        with self.assertNoLogs("zentral.pbac.utils", level="WARNING"), \
             self.captureOnCommitCallbacks(execute=True):
            response = self.post(self.es_list_url(), payload)
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(self.es_secret(response.json()))
        self.assertEqual(self.es_events(post_event), [])
        self.es_set_policies(("permit", "resource"), permissions=(add_permission,))
        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            response = self.post(self.es_list_url(), payload)
        self.assertEqual(response.status_code, 201)
        created = type(enrollment).objects.get(pk=response.json()["id"])
        self.assertEqual(self.es_secret(response.json()), self.es_stored_secret(created))
        # sent on commit only
        self.assertEqual(self.es_events(post_event), [])
        for callback in callbacks:
            callback()
        events = self.es_events(post_event)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].payload["where"], "api_create")
        self.assertEqual(self.es_event_pks(events[0]), [created.pk])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_es_update_response(self, post_event):
        enrollment = self.es_force_enrollment(self.mbu)
        payload = self.es_write_payload(enrollment, self.mbu)
        if payload is None:
            self.skipTest("no write")
        change_permission = f"{self.es_app_label}.change_enrollment"
        # a no-op update does not read a secret that a forbid refuses
        self.es_set_policies(("permit", "resource"), ("forbid", self.es_in_mbu(self.mbu)),
                             permissions=(change_permission,))
        with self.assertNoLogs("zentral.pbac.utils", level="WARNING"), \
             self.captureOnCommitCallbacks(execute=True):
            response = self.put(self.es_detail_url(enrollment), payload)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.es_secret(response.json()))
        self.assertEqual(self.es_events(post_event), [])
        self.es_set_policies(("permit", "resource"), permissions=(change_permission,))
        with self.captureOnCommitCallbacks(execute=True):
            response = self.put(self.es_detail_url(enrollment), payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.es_secret(response.json()), self.es_stored_secret(enrollment))
        events = self.es_events(post_event)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].payload["where"], "api_update")

    # downloads

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_es_downloads(self, post_event):
        enrollment = self.es_force_enrollment(self.mbu)
        other_enrollment = self.es_force_enrollment(self.other_mbu)
        urls = self.es_download_urls(enrollment)
        if not urls:
            self.skipTest("no download")
        other_urls = self.es_download_urls(other_enrollment)
        # the action alone: the view permission opens the download
        self.es_set_policies(("permit", "resource"))
        for url in urls:
            self.assertEqual(self.get(url).status_code, 403)
        # the view permission alone: the download is the secret
        self.es_set_policies(permissions=(self.es_view_permission,))
        for url in urls:
            with self.assertLogs("zentral.pbac.utils", level="WARNING"):
                self.assertEqual(self.get(url).status_code, 403)
        # the view permission, and the action in one business unit
        self.es_set_policies(("permit", self.es_in_mbu(self.mbu)), permissions=(self.es_view_permission,))
        for url, other_url in zip(urls, other_urls):
            self.assertEqual(self.get(url).status_code, 200)
            with self.assertLogs("zentral.pbac.utils", level="WARNING"):
                self.assertEqual(self.get(other_url).status_code, 403)
        events = self.es_events(post_event)
        self.assertEqual(len(events), len(urls))
        self.assertTrue(all(event.payload["where"].startswith("download:") for event in events))
        self.assertTrue(all(self.es_event_pks(event) == [enrollment.pk] for event in events))

    def test_es_refused_download_builds_nothing(self):
        enrollment = self.es_force_enrollment(self.mbu)
        urls = self.es_download_urls(enrollment)
        if not urls:
            self.skipTest("no download")
        self.es_set_policies(permissions=(self.es_view_permission,))
        # a package builder makes its build directory when it is created. wraps: a regression builds in a real
        # temporary directory, not in the working directory
        with patch("zentral.utils.osx_package.tempfile.mkdtemp", wraps=tempfile.mkdtemp) as mkdtemp:
            for url in urls:
                with self.assertLogs("zentral.pbac.utils", level="WARNING"):
                    self.assertEqual(self.get(url).status_code, 403)
        mkdtemp.assert_not_called()

    # console

    def test_es_page_links(self):
        enrollment = self.es_force_enrollment(self.mbu)
        page = self.es_page(enrollment)
        if page is None:
            self.skipTest("no page")
        url, links = page
        self.es_set_policies(permissions=(self.es_view_permission,) + tuple(self.es_page_permissions))
        self.client.force_login(self.user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        for link in links:
            self.assertNotContains(response, link)
        self.es_set_policies(("permit", "resource"),
                             permissions=(self.es_view_permission,) + tuple(self.es_page_permissions))
        response = self.client.get(url)
        for link in links:
            self.assertContains(response, link)
