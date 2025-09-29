from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.mdm.models import (
    Artifact,
    ArtifactVersion,
    ArtifactVersionTag,
    DeviceArtifact,
    TargetArtifact,
)
from zentral.core.events.base import AuditEvent
from .utils import (
    force_acme_issuer,
    force_artifact,
    force_blueprint_artifact,
    force_dep_enrollment_session,
    force_scep_issuer,
)


@override_settings(
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage"
)
class MDMCertAssetsAPIViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True,
        )
        cls.user = User.objects.create_user(
            "godzilla", "godzilla@zentral.io", get_random_string(12)
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)

    # utility methods

    def set_permissions(self, *permissions):
        if permissions:
            permission_filter = reduce(
                operator.or_,
                (
                    Q(content_type__app_label=app_label, codename=codename)
                    for app_label, codename in (
                        permission.split(".") for permission in permissions
                    )
                ),
            )
            self.group.permissions.set(
                list(Permission.objects.filter(permission_filter))
            )
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

    # list cert assets

    def test_list_cert_assets_unauthorized(self):
        response = self.get(reverse("mdm_api:cert_assets"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_cert_assets_permission_denied(self):
        response = self.get(reverse("mdm_api:cert_assets"))
        self.assertEqual(response.status_code, 403)

    def test_list_cert_assets(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.CERT_ASSET)
        self.set_permissions("mdm.view_certasset")
        response = self.get(reverse("mdm_api:cert_assets"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            [
                {
                    "accessible": "Default",
                    "acme_issuer": str(ea_av.cert_asset.acme_issuer.pk),
                    "artifact": str(artifact.pk),
                    "created_at": ea_av.created_at.isoformat(),
                    "default_shard": 100,
                    "excluded_tags": [],
                    "id": str(ea_av.pk),
                    "ios": False,
                    "ios_max_version": "",
                    "ios_min_version": "",
                    "ipados": False,
                    "ipados_max_version": "",
                    "ipados_min_version": "",
                    "macos": True,
                    "macos_max_version": "",
                    "macos_min_version": "",
                    "scep_issuer": str(ea_av.cert_asset.scep_issuer.pk),
                    "shard_modulo": 100,
                    "subject": [{"type": "CN", "value": "YOLO"}],
                    "subject_alt_name": {
                        "dNSName": "yolo.example.com",
                        "ntPrincipalName": "yolo@example.com",
                        "rfc822Name": "yolo@example.com",
                        "uniformResourceIdentifier": "https://example.com/yolo",
                    },
                    "tag_shards": [],
                    "tvos": False,
                    "tvos_max_version": "",
                    "tvos_min_version": "",
                    "updated_at": ea_av.updated_at.isoformat(),
                    "version": 1,
                }
            ],
        )

    # create cert asset

    def test_create_cert_asset_unauthorized(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.CERT_ASSET)
        acme_issuer = force_acme_issuer()
        response = self.post(
            reverse("mdm_api:cert_assets"),
            data={
                "artifact": str(artifact.pk),
                "acme_issuer": str(acme_issuer.pk),
                "scep_issuer": None,
                "subject": [{"type": "CN", "value": "yolo"}],
                "subject_alt_name": {},
                "accessible": "Default",
                "macos": True,
                "version": 1,
            },
            include_token=False,
        )
        self.assertEqual(response.status_code, 401)

    def test_create_cert_asset_permission_denied(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.CERT_ASSET)
        acme_issuer = force_acme_issuer()
        response = self.post(
            reverse("mdm_api:cert_assets"),
            data={
                "artifact": str(artifact.pk),
                "acme_issuer": str(acme_issuer.pk),
                "scep_issuer": None,
                "subject": [{"type": "CN", "value": "yolo"}],
                "subject_alt_name": {},
                "accessible": "Default",
                "macos": True,
                "version": 1,
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_create_cert_asset_missing_fields_error(self):
        _, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        self.set_permissions("mdm.add_certasset")
        response = self.post(
            reverse("mdm_api:cert_assets"),
            data={"artifact": str(artifact.pk), "macos": True, "version": 1},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {
                "acme_issuer": ["This field is required."],
                "scep_issuer": ["This field is required."],
                "subject": ["This field is required."],
                "subject_alt_name": ["This field is required."],
            },
        )

    def test_create_cert_asset_missing_issuer_error(self):
        _, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        self.set_permissions("mdm.add_certasset")
        response = self.post(
            reverse("mdm_api:cert_assets"),
            data={
                "artifact": str(artifact.pk),
                "acme_issuer": None,
                "scep_issuer": None,
                "subject": [{"type": "CN", "value": "yolo"}],
                "subject_alt_name": {},
                "accessible": "Default",
                "macos": True,
                "version": 2,
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"non_field_errors": ["An ACME issuer or SCEP issuer is required."]},
        )

    def test_create_cert_asset_plist_file_extension_error(self):
        _, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        acme_issuer = force_acme_issuer()
        self.set_permissions("mdm.add_certasset")
        response = self.post(
            reverse("mdm_api:cert_assets"),
            data={
                "artifact": str(artifact.pk),
                "acme_issuer": str(acme_issuer.pk),
                "scep_issuer": None,
                "subject": [],
                "subject_alt_name": {},
                "accessible": "Default",
                "macos": True,
                "version": 2,
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"non_field_errors": ["A Subject or SubjectAltName is required."]},
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_cert_asset(self, post_event):
        blueprint_artifact, artifact, _ = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET,
        )
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(
            len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1
        )
        acme_issuer = force_acme_issuer()
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        self.set_permissions("mdm.add_certasset")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:cert_assets"),
                data={
                    "artifact": str(artifact.pk),
                    "acme_issuer": str(acme_issuer.pk),
                    "scep_issuer": None,
                    "subject": [{"type": "CN", "value": "yolo"}],
                    "subject_alt_name": {},
                    "accessible": "Default",
                    "macos": True,
                    "macos_max_version": "",  # blank OK
                    "macos_min_version": "13.3.1",
                    "excluded_tags": [excluded_tag.pk],
                    "shard_modulo": 10,
                    "default_shard": 0,
                    "tag_shards": [{"tag": shard_tag.pk, "shard": 5}],
                    "version": 17,
                },
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        ea_av = artifact.artifactversion_set.all().order_by("-created_at").first()
        self.assertEqual(
            data,
            {
                "id": str(ea_av.pk),
                "accessible": "Default",
                "acme_issuer": str(acme_issuer.pk),
                "artifact": str(artifact.pk),
                "default_shard": 0,
                "excluded_tags": [excluded_tag.pk],
                "ios": False,
                "ios_max_version": "",
                "ios_min_version": "",
                "ipados": False,
                "ipados_max_version": "",
                "ipados_min_version": "",
                "macos": True,
                "macos_max_version": "",
                "macos_min_version": "13.3.1",
                "scep_issuer": None,
                "shard_modulo": 10,
                "subject": [{"type": "CN", "value": "yolo"}],
                "subject_alt_name": {
                    "dNSName": None,
                    "ntPrincipalName": None,
                    "rfc822Name": None,
                    "uniformResourceIdentifier": None,
                },
                "tag_shards": [{"tag": shard_tag.pk, "shard": 5}],
                "tvos": False,
                "tvos_max_version": "",
                "tvos_min_version": "",
                "version": 17,
                "created_at": ea_av.created_at.isoformat(),
                "updated_at": ea_av.updated_at.isoformat(),
            },
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {
                "action": "created",
                "object": {
                    "model": "mdm.certasset",
                    "pk": str(ea_av.cert_asset.pk),
                    "new_value": {
                        "pk": str(ea_av.pk),
                        "accessible": "Default",
                        "acme_issuer": {
                            "pk": str(acme_issuer.pk),
                            "name": acme_issuer.name,
                        },
                        "artifact": {"pk": str(artifact.pk), "name": artifact.name},
                        "default_shard": 0,
                        "excluded_tags": [
                            {"pk": excluded_tag.pk, "name": excluded_tag.name}
                        ],
                        "ios": False,
                        "ios_max_version": "",
                        "ios_min_version": "",
                        "ipados": False,
                        "ipados_max_version": "",
                        "ipados_min_version": "",
                        "macos": True,
                        "macos_max_version": "",
                        "macos_min_version": "13.3.1",
                        "scep_issuer": None,
                        "shard_modulo": 10,
                        "subject": [{"type": "CN", "value": "yolo"}],
                        "subject_alt_name": {},
                        "tag_shards": [
                            {
                                "tag": {"pk": shard_tag.pk, "name": shard_tag.name},
                                "shard": 5,
                            }
                        ],
                        "tvos": False,
                        "tvos_max_version": "",
                        "tvos_min_version": "",
                        "version": 17,
                        "created_at": ea_av.created_at,
                        "updated_at": ea_av.updated_at,
                    },
                },
            },
        )
        metadata = event.metadata.serialize()
        self.assertEqual(
            metadata["objects"], {"mdm_cert_asset": [str(ea_av.cert_asset.pk)]}
        )
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(
            len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 2
        )

    # get cert asset

    def test_get_cert_asset_unauthorized(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.CERT_ASSET)
        response = self.get(
            reverse("mdm_api:cert_asset", args=(ea_av.pk,)), include_token=False
        )
        self.assertEqual(response.status_code, 401)

    def test_get_cert_asset_permission_denied(self):
        artifact, (ea_av,) = force_artifact()
        response = self.get(reverse("mdm_api:cert_asset", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_artifact(self):
        force_artifact()
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.CERT_ASSET)
        self.set_permissions("mdm.view_certasset")
        response = self.get(reverse("mdm_api:cert_asset", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            {
                "accessible": "Default",
                "acme_issuer": str(ea_av.cert_asset.acme_issuer.pk),
                "artifact": str(artifact.pk),
                "created_at": ea_av.created_at.isoformat(),
                "default_shard": 100,
                "excluded_tags": [],
                "id": str(ea_av.pk),
                "ios": False,
                "ios_max_version": "",
                "ios_min_version": "",
                "ipados": False,
                "ipados_max_version": "",
                "ipados_min_version": "",
                "macos": True,
                "macos_max_version": "",
                "macos_min_version": "",
                "scep_issuer": str(ea_av.cert_asset.scep_issuer.pk),
                "shard_modulo": 100,
                "subject": [{"type": "CN", "value": "YOLO"}],
                "subject_alt_name": {
                    "dNSName": "yolo.example.com",
                    "ntPrincipalName": "yolo@example.com",
                    "rfc822Name": "yolo@example.com",
                    "uniformResourceIdentifier": "https://example.com/yolo",
                },
                "tag_shards": [],
                "tvos": False,
                "tvos_max_version": "",
                "tvos_min_version": "",
                "updated_at": ea_av.updated_at.isoformat(),
                "version": 1,
            },
        )

    # update cert asset

    def test_update_cert_asset_unauthorized(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.CERT_ASSET)
        response = self.put(
            reverse("mdm_api:cert_asset", args=(ea_av.pk,)),
            data={
                "artifact": str(artifact.pk),
                "type": "ZIP",
                "file_uri": "s3://yolo/fomo.zip",
                "file_sha256": 64 * "0",
                "macos": True,
                "version": 1,
            },
            include_token=False,
        )
        self.assertEqual(response.status_code, 401)

    def test_update_cert_asset_permission_denied(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.CERT_ASSET)
        response = self.put(
            reverse("mdm_api:cert_asset", args=(ea_av.pk,)),
            data={
                "artifact": str(artifact.pk),
                "type": "ZIP",
                "file_uri": "s3://yolo/fomo.zip",
                "file_sha256": 64 * "0",
                "macos": True,
                "version": 1,
            },
        )
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_cert_asset(self, post_event):
        blueprint_artifact, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(
            blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0][
                "excluded_tags"
            ],
            [],
        )
        ea_av.excluded_tags.set([Tag.objects.create(name=get_random_string(12))])
        ea_av.cert_asset.save()
        ArtifactVersionTag.objects.create(
            artifact_version=ea_av,
            tag=Tag.objects.create(name=get_random_string(12)),
            shard=1,
        )
        prev_value = ea_av.cert_asset.serialize_for_event()
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        scep_issuer = force_scep_issuer()
        self.set_permissions("mdm.change_certasset")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(
                reverse("mdm_api:cert_asset", args=(ea_av.pk,)),
                data={
                    "accessible": "AfterFirstUnlock",
                    "artifact": str(artifact.pk),
                    "acme_issuer": None,
                    "scep_issuer": str(scep_issuer.pk),
                    "subject": [],
                    "subject_alt_name": {"rfc822Name": "yolo@zentral.com"},
                    "macos": True,
                    "macos_min_version": "13.3.1",
                    "excluded_tags": [excluded_tag.pk],
                    "shard_modulo": 10,
                    "default_shard": 0,
                    "tag_shards": [{"tag": shard_tag.pk, "shard": 5}],
                    "version": 17,
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        ea_av.refresh_from_db()
        self.assertEqual(
            data,
            {
                "accessible": "AfterFirstUnlock",
                "acme_issuer": None,
                "artifact": str(artifact.pk),
                "created_at": ea_av.created_at.isoformat(),
                "default_shard": 0,
                "excluded_tags": [excluded_tag.pk],
                "id": str(ea_av.pk),
                "ios": False,
                "ios_max_version": "",
                "ios_min_version": "",
                "ipados": False,
                "ipados_max_version": "",
                "ipados_min_version": "",
                "macos": True,
                "macos_max_version": "",
                "macos_min_version": "13.3.1",
                "scep_issuer": str(scep_issuer.pk),
                "shard_modulo": 10,
                "subject": [],
                "subject_alt_name": {
                    "dNSName": None,
                    "ntPrincipalName": None,
                    "rfc822Name": "yolo@zentral.com",
                    "uniformResourceIdentifier": None,
                },
                "tag_shards": [{"shard": 5, "tag": shard_tag.pk}],
                "tvos": False,
                "tvos_max_version": "",
                "tvos_min_version": "",
                "updated_at": ea_av.updated_at.isoformat(),
                "version": 17,
            },
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {
                "action": "updated",
                "object": {
                    "model": "mdm.certasset",
                    "pk": str(ea_av.cert_asset.pk),
                    "new_value": {
                        "pk": str(ea_av.pk),
                        "accessible": "AfterFirstUnlock",
                        "acme_issuer": None,
                        "artifact": {"pk": str(artifact.pk), "name": artifact.name},
                        "default_shard": 0,
                        "excluded_tags": [
                            {"pk": excluded_tag.pk, "name": excluded_tag.name}
                        ],
                        "ios": False,
                        "ios_max_version": "",
                        "ios_min_version": "",
                        "ipados": False,
                        "ipados_max_version": "",
                        "ipados_min_version": "",
                        "macos": True,
                        "macos_max_version": "",
                        "macos_min_version": "13.3.1",
                        "scep_issuer": {
                            "pk": str(scep_issuer.pk),
                            "name": scep_issuer.name,
                        },
                        "shard_modulo": 10,
                        "subject": [],
                        "subject_alt_name": {"rfc822Name": "yolo@zentral.com"},
                        "tag_shards": [
                            {
                                "tag": {"pk": shard_tag.pk, "name": shard_tag.name},
                                "shard": 5,
                            }
                        ],
                        "tvos": False,
                        "tvos_max_version": "",
                        "tvos_min_version": "",
                        "version": 17,
                        "created_at": ea_av.created_at,
                        "updated_at": ea_av.updated_at,
                    },
                    "prev_value": prev_value,
                },
            },
        )
        metadata = event.metadata.serialize()
        self.assertEqual(
            metadata["objects"], {"mdm_cert_asset": [str(ea_av.cert_asset.pk)]}
        )
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(
            blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0][
                "excluded_tags"
            ],
            [excluded_tag.pk],
        )

    # delete cert asset

    def test_delete_cert_asset_unauthorized(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.CERT_ASSET)
        response = self.delete(
            reverse("mdm_api:cert_asset", args=(ea_av.pk,)), include_token=False
        )
        self.assertEqual(response.status_code, 401)

    def test_delete_cert_asset_permission_denied(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.CERT_ASSET)
        response = self.delete(reverse("mdm_api:cert_asset", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_cert_asset_cannot_be_deleted(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.CERT_ASSET)
        session, _, _ = force_dep_enrollment_session(
            MetaBusinessUnit.objects.create(name=get_random_string(12)), completed=True
        )
        DeviceArtifact.objects.create(
            enrolled_device=session.enrolled_device,
            artifact_version=ea_av,
            status=TargetArtifact.Status.INSTALLED,
        )
        self.set_permissions("mdm.delete_certasset")
        response = self.delete(reverse("mdm_api:cert_asset", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This cert asset cannot be deleted"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_cert_asset(self, post_event):
        blueprint_artifact, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(
            len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1
        )
        self.assertEqual(
            blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["pk"],
            str(ea_av.pk),
        )
        prev_value = ea_av.cert_asset.serialize_for_event()
        self.set_permissions("mdm.delete_certasset")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:cert_asset", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {
                "action": "deleted",
                "object": {
                    "model": "mdm.certasset",
                    "pk": str(ea_av.cert_asset.pk),
                    "prev_value": prev_value,
                },
            },
        )
        metadata = event.metadata.serialize()
        self.assertEqual(
            metadata["objects"], {"mdm_cert_asset": [str(ea_av.cert_asset.pk)]}
        )
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        self.assertEqual(ArtifactVersion.objects.filter(pk=ea_av.pk).count(), 0)
        blueprint.refresh_from_db()
        self.assertEqual(
            len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 0
        )
