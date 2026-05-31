import uuid
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from tests.utils.packages import build_dummy_package
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.app_manifest import read_package_info
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.declarations.exceptions import (
    TokenSessionNotFoundError,
    TokenUserNotFoundError,
)
from zentral.contrib.mdm.declarations.packages import (
    dump_package_file_token,
    dump_package_manifest_token,
)
from zentral.contrib.mdm.declarations.utils import (
    dump_artifact_version_token,
    load_artifact_version_token,
)
from zentral.contrib.mdm.events.downloads import (
    MDMDownloadEvent,
    post_mdm_download_error_event,
)
from zentral.contrib.mdm.models import Artifact, Package
from zentral.core.events.base import EventMetadata

from .utils import force_dep_enrollment_session, force_enrolled_user


@patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
class MDMDownloadEventTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        package_bytes = build_dummy_package(name="dlevent", version="1.0", product_archive_title="dlevent")
        uploaded = SimpleUploadedFile("dlevent.pkg", package_bytes)
        _, _, pkg_data = read_package_info(uploaded, compute_sha256=True)
        uploaded.seek(0)
        cls.package = Package.objects.create(
            name=get_random_string(12),
            description="",
            type=Package.Type.PKG,
            file=uploaded,
            filename=uploaded.name,
            sha256=pkg_data["package_sha256"],
            size=pkg_data["package_size"],
            product_id=pkg_data["product_id"],
            product_version=pkg_data["product_version"],
            bundles=pkg_data["bundles"],
            manifest=pkg_data["manifest"],
        )

    # helpers

    def _build_session(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        return session

    def _captured_event(self, post_event):
        self.assertEqual(post_event.call_count, 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDownloadEvent)
        return event

    # event class shape

    def test_get_linked_objects_keys_full(self, post_event):
        event = MDMDownloadEvent(
            EventMetadata(),
            {
                "outcome": "success",
                "target_type": "package_manifest",
                "enrolled_device": {"pk": 17, "udid": "U1", "serial_number": "S1"},
                "enrolled_user": {"pk": 42, "user_id": "USER42"},
                "package": {"pk": "pkg-uuid"},
            },
        )
        self.assertEqual(
            event.get_linked_objects_keys(),
            {
                "mdm_enrolleddevice": [(17,)],
                "mdm_enrolleduser": [(42,)],
                "mdm_package": [("pkg-uuid",)],
            },
        )

    def test_get_linked_objects_keys_with_artifact_version(self, post_event):
        event = MDMDownloadEvent(
            EventMetadata(),
            {
                "outcome": "success",
                "target_type": "data_asset",
                "data_asset": {"pk": "av-uuid", "artifact": {"pk": "a-uuid"}},
            },
        )
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"mdm_artifactversion": [("av-uuid",)], "mdm_artifact": [("a-uuid",)]},
        )

    def test_get_linked_objects_keys_minimal(self, post_event):
        event = MDMDownloadEvent(EventMetadata(), {"outcome": "bad_token"})
        self.assertEqual(event.get_linked_objects_keys(), {})

    def test_get_linked_objects_keys_enrollment_session(self, post_event):
        event = MDMDownloadEvent(
            EventMetadata(),
            {
                "outcome": "session_not_found",
                "target_type": "package_manifest",
                "package": {"pk": "pkg-uuid"},
                "enrollment_session": {"model": "depenrollmentsession", "pk": "42"},
            },
        )
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"mdm_package": [("pkg-uuid",)], "mdm_depenrollmentsession": [("42",)]},
        )

    # success path: package_manifest

    def test_package_manifest_success_emits_event(self, post_event):
        package = self.package
        session = self._build_session()
        token = dump_package_manifest_token(session, Target(session.enrolled_device), package.pk)
        response = self.client.get(reverse("mdm_public:package_manifest", args=(token,)))
        self.assertEqual(response.status_code, 200)
        event = self._captured_event(post_event)
        self.assertEqual(event.payload["outcome"], "success")
        self.assertEqual(event.payload["target_type"], "package_manifest")
        self.assertEqual(event.payload["response_kind"], "stream")
        self.assertEqual(event.payload["package"]["pk"], str(package.pk))
        # full Package.serialize_for_event is embedded
        self.assertEqual(event.payload["package"]["product_id"], package.product_id)
        # enrolled_device serialized (full)
        enrolled_device = session.enrolled_device
        self.assertEqual(event.payload["enrolled_device"]["udid"], enrolled_device.udid)
        self.assertEqual(event.payload["enrolled_device"]["serial_number"], enrolled_device.serial_number)
        self.assertEqual(event.payload["enrolled_device"]["platform"], enrolled_device.platform)
        # metadata
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], enrolled_device.serial_number)
        self.assertEqual(
            metadata["objects"],
            {
                "mdm_enrolleddevice": [str(enrolled_device.pk)],
                "mdm_package": [str(package.pk)],
            },
        )
        self.assertEqual(metadata["tags"], ["mdm"])
        # EventRequest captured
        self.assertEqual(metadata["request"]["view"], "mdm_public:package_manifest")

    # success path: package_file (redirect branch)

    @patch("zentral.contrib.mdm.public_views.mdm.file_storage_has_signed_urls")
    def test_package_file_redirect_response_kind(self, file_storage_has_signed_urls, post_event):
        file_storage_has_signed_urls.return_value = True
        package = self.package
        session = self._build_session()
        token = dump_package_file_token(session, Target(session.enrolled_device), package.pk)
        response = self.client.get(reverse("mdm_public:package_file", args=(token,)))
        self.assertEqual(response.status_code, 302)
        event = self._captured_event(post_event)
        self.assertEqual(event.payload["target_type"], "package_file")
        self.assertEqual(event.payload["response_kind"], "redirect")

    # bad_token: posts an event, returns 400

    def test_bad_token_emits_event(self, post_event):
        response = self.client.get(reverse("mdm_public:package_manifest", args=("not-a-token",)))
        self.assertEqual(response.status_code, 400)
        event = self._captured_event(post_event)
        self.assertEqual(event.payload["outcome"], "bad_token")
        self.assertNotIn("target_type", event.payload)
        self.assertNotIn("enrolled_device", event.payload)
        metadata = event.metadata.serialize()
        self.assertNotIn("machine_serial_number", metadata)
        # request captured (the view that was hit is still resolvable)
        self.assertEqual(metadata["request"]["view"], "mdm_public:package_manifest")

    # target_not_found: posts an event with the missing pk, returns 404

    def test_target_not_found_emits_event(self, post_event):
        session = self._build_session()
        missing_pk = uuid.uuid4()
        token = dump_package_manifest_token(session, Target(session.enrolled_device), missing_pk)
        response = self.client.get(reverse("mdm_public:package_manifest", args=(token,)))
        self.assertEqual(response.status_code, 404)
        event = self._captured_event(post_event)
        self.assertEqual(event.payload["outcome"], "target_not_found")
        self.assertEqual(event.payload["target_type"], "package_manifest")
        # The target key carries a sparse dict — only the pk.
        self.assertEqual(event.payload["package"], {"pk": str(missing_pk)})
        # No enrolled_device — the loader never got that far.
        self.assertNotIn("enrolled_device", event.payload)
        # linked_objects still picks up the package via its pk.
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_package": [str(missing_pk)]})

    # session_not_found: target resolves, session lookup fails

    def test_session_not_found_emits_event(self, post_event):
        package = self.package
        session = self._build_session()
        token = dump_package_manifest_token(session, Target(session.enrolled_device), package.pk)
        # nuke the session after the token was minted
        session_pk = session.pk
        session_model_name = session._meta.model_name
        session.delete()
        response = self.client.get(reverse("mdm_public:package_manifest", args=(token,)))
        self.assertEqual(response.status_code, 404)
        event = self._captured_event(post_event)
        self.assertEqual(event.payload["outcome"], "session_not_found")
        self.assertEqual(event.payload["target_type"], "package_manifest")
        # full package dict because the target DID resolve.
        self.assertEqual(event.payload["package"]["pk"], str(package.pk))
        self.assertEqual(event.payload["package"]["product_id"], package.product_id)
        # missing session info
        self.assertEqual(event.payload["enrollment_session"]["model"], session_model_name)
        self.assertEqual(event.payload["enrollment_session"]["pk"], str(session_pk))
        # no enrolled_device — session didn't resolve, so no device pulled either.
        self.assertNotIn("enrolled_device", event.payload)
        metadata = event.metadata.serialize()
        # both the package and the missing session show up as linked objects.
        self.assertEqual(
            metadata["objects"],
            {
                "mdm_package": [str(package.pk)],
                f"mdm_{session_model_name}": [str(session_pk)],
            },
        )

    # user_not_found: target + session resolve, enrolled_user lookup fails

    def test_user_not_found_emits_event(self, post_event):
        package = self.package
        session = self._build_session()
        enrolled_user = force_enrolled_user(session.enrolled_device)
        token = dump_package_manifest_token(
            session, Target(session.enrolled_device, enrolled_user), package.pk
        )
        # nuke the user after the token was minted
        user_pk = enrolled_user.pk
        enrolled_user.delete()
        response = self.client.get(reverse("mdm_public:package_manifest", args=(token,)))
        self.assertEqual(response.status_code, 404)
        event = self._captured_event(post_event)
        self.assertEqual(event.payload["outcome"], "user_not_found")
        self.assertEqual(event.payload["target_type"], "package_manifest")
        # full dicts for the things that resolved
        self.assertEqual(event.payload["package"]["pk"], str(package.pk))
        self.assertEqual(event.payload["enrolled_device"]["udid"], session.enrolled_device.udid)
        # sparse enrolled_user — just the pk.
        self.assertEqual(event.payload["enrolled_user"], {"pk": str(user_pk)})
        metadata = event.metadata.serialize()
        # the missing user is still queryable via linked_objects.
        self.assertEqual(
            metadata["objects"]["mdm_enrolleduser"], [str(user_pk)]
        )
        # machine_serial_number is set because the device DID resolve.
        self.assertEqual(metadata["machine_serial_number"], session.enrolled_device.serial_number)

    # success path crosses through to file URL too

    def test_full_round_trip_emits_two_events(self, post_event):
        package = self.package
        session = self._build_session()
        manifest_token = dump_package_manifest_token(session, Target(session.enrolled_device), package.pk)
        # 1) fetch manifest
        response = self.client.get(reverse("mdm_public:package_manifest", args=(manifest_token,)))
        self.assertEqual(response.status_code, 200)
        # 2) follow the embedded file URL
        import plistlib
        url = plistlib.loads(response.content)["items"][0]["assets"][0]["url"]
        path = "/" + url.split("/", 3)[3]
        response2 = self.client.get(path)
        self.assertEqual(response2.status_code, 200)
        # two events posted, in order
        self.assertEqual(post_event.call_count, 2)
        ev1, ev2 = post_event.call_args_list[0].args[0], post_event.call_args_list[1].args[0]
        self.assertEqual(ev1.payload["target_type"], "package_manifest")
        self.assertEqual(ev2.payload["target_type"], "package_file")
        # both reference the same package
        self.assertEqual(ev1.payload["package"]["pk"], ev2.payload["package"]["pk"])

    # device_inactive: blocked and checked_out

    def test_device_inactive_blocked_emits_event(self, post_event):
        from django.utils.timezone import now
        package = self.package
        session = self._build_session()
        token = dump_package_manifest_token(session, Target(session.enrolled_device), package.pk)
        session.enrolled_device.blocked_at = now()
        session.enrolled_device.save()
        response = self.client.get(reverse("mdm_public:package_manifest", args=(token,)))
        self.assertEqual(response.status_code, 404)
        event = self._captured_event(post_event)
        self.assertEqual(event.payload["outcome"], "device_inactive")
        self.assertEqual(event.payload["reason"], "blocked")
        self.assertEqual(event.payload["target_type"], "package_manifest")
        self.assertEqual(event.payload["package"]["pk"], str(package.pk))
        self.assertEqual(
            event.payload["enrolled_device"]["udid"], session.enrolled_device.udid
        )
        # machine_serial_number on metadata
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], session.enrolled_device.serial_number)

    def test_device_inactive_checked_out_emits_event(self, post_event):
        from django.utils.timezone import now
        package = self.package
        session = self._build_session()
        token = dump_package_manifest_token(session, Target(session.enrolled_device), package.pk)
        session.enrolled_device.checkout_at = now()
        session.enrolled_device.save()
        response = self.client.get(reverse("mdm_public:package_manifest", args=(token,)))
        self.assertEqual(response.status_code, 404)
        event = self._captured_event(post_event)
        self.assertEqual(event.payload["outcome"], "device_inactive")
        self.assertEqual(event.payload["reason"], "checked_out")

    # device_inactive on artifact_version loader

    def test_artifact_version_loader_device_inactive(self, post_event):
        from django.utils.timezone import now
        from zentral.contrib.mdm.declarations.exceptions import TokenDeviceInactiveError
        from .utils import force_artifact
        artifact, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.PROFILE)
        session = self._build_session()
        token = dump_artifact_version_token(
            session, Target(session.enrolled_device), artifact_version.pk,
            "zentral_legacy_profile",
        )
        session.enrolled_device.blocked_at = now()
        session.enrolled_device.save()
        with self.assertRaises(TokenDeviceInactiveError) as cm:
            load_artifact_version_token(token, Artifact.Type.PROFILE, "zentral_legacy_profile")
        self.assertEqual(cm.exception.reason, "blocked")
        self.assertEqual(cm.exception.target.pk, artifact_version.pk)
        self.assertEqual(cm.exception.enrollment_session.pk, session.pk)

    # exception class: reject unknown reason

    def test_token_device_inactive_error_rejects_unknown_reason(self, post_event):
        from zentral.contrib.mdm.declarations.exceptions import TokenDeviceInactiveError
        with self.assertRaises(ValueError):
            TokenDeviceInactiveError(target=None, enrollment_session=None, reason="bogus")

    def test_check_device_inactive_no_device(self, post_event):
        # A session that hasn't acquired its EnrolledDevice yet must not trip
        # the device-state guard.
        from types import SimpleNamespace
        from zentral.contrib.mdm.declarations.utils import _check_device_inactive
        session = SimpleNamespace(enrolled_device=None)
        # no exception raised
        self.assertIsNone(_check_device_inactive(target=None, enrollment_session=session))

    # artifact_version loader: session_not_found and user_not_found

    def test_artifact_version_loader_session_not_found(self, post_event):
        from .utils import force_artifact
        artifact, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.PROFILE)
        session = self._build_session()
        token = dump_artifact_version_token(
            session, Target(session.enrolled_device), artifact_version.pk,
            "zentral_legacy_profile",
        )
        session_pk = session.pk
        session_model_name = session._meta.model_name
        session.delete()
        with self.assertRaises(TokenSessionNotFoundError) as cm:
            load_artifact_version_token(token, Artifact.Type.PROFILE, "zentral_legacy_profile")
        self.assertEqual(cm.exception.target.pk, artifact_version.pk)
        self.assertEqual(cm.exception.session_model, session_model_name)
        self.assertEqual(cm.exception.session_pk, session_pk)

    def test_artifact_version_loader_user_not_found(self, post_event):
        from .utils import force_artifact
        artifact, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.PROFILE)
        session = self._build_session()
        enrolled_user = force_enrolled_user(session.enrolled_device)
        token = dump_artifact_version_token(
            session, Target(session.enrolled_device, enrolled_user), artifact_version.pk,
            "zentral_legacy_profile",
        )
        user_pk = enrolled_user.pk
        enrolled_user.delete()
        with self.assertRaises(TokenUserNotFoundError) as cm:
            load_artifact_version_token(token, Artifact.Type.PROFILE, "zentral_legacy_profile")
        self.assertEqual(cm.exception.target.pk, artifact_version.pk)
        self.assertEqual(cm.exception.enrollment_session.pk, session.pk)
        self.assertEqual(cm.exception.user_pk, user_pk)

    # safeguard: unexpected exception type → ValueError

    def test_post_mdm_download_error_event_unexpected_exception(self, post_event):
        class NotATokenError(Exception):
            pass

        # Build a fake request that has the minimum attrs EventRequest needs.
        from django.test import RequestFactory
        request = RequestFactory().get("/foo/")

        class StubView:
            target_type = "package_manifest"
            target_key = "package"

        with self.assertRaises(ValueError):
            post_mdm_download_error_event(request, StubView(), NotATokenError())
