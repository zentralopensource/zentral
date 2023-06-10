import base64
import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import Tag
from zentral.contrib.mdm.models import ArtifactVersionTag
from zentral.contrib.mdm.serializers import ProfileSerializer
from .utils import build_mobileconfig_data, force_artifact


class MDMSerializersTestCase(TestCase):
    def test_serialize_profile(self):
        artifact, (profile_av,) = force_artifact()
        profile_av.macos_min_version = "13.3.1"
        profile_av.save()
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        profile_av.excluded_tags.add(excluded_tag)
        shard_tag = Tag.objects.create(name=get_random_string(12))
        ArtifactVersionTag.objects.create(artifact_version=profile_av, tag=shard_tag, shard=77)
        serializer = ProfileSerializer(profile_av.profile)
        data = serializer.data
        self.assertTrue(data["macos"])
        self.assertEqual(data["macos_min_version"], "13.3.1")
        self.assertEqual(data["excluded_tags"], [excluded_tag.pk])
        self.assertEqual(data["tag_shards"], [{"tag": shard_tag.pk, "shard": 77}])
        payload = plistlib.loads(base64.b64decode(data["source"]))
        self.assertEqual(payload["PayloadType"], "Configuration")

    def test_profile_platform_not_available_error(self):
        artifact, (profile_av,) = force_artifact()
        serializer = ProfileSerializer(data={
            "artifact": str(artifact.pk),
            "source": base64.b64encode(build_mobileconfig_data()),
            "tvos": True,
            "version": 1,
        })
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["tvos"][0]
        self.assertEqual(str(ed), "Platform not available for this artifact")

    def test_profile_at_least_one_platform_error(self):
        artifact, (profile_av,) = force_artifact()
        serializer = ProfileSerializer(data={
            "artifact": str(artifact.pk),
            "source": base64.b64encode(build_mobileconfig_data()),
            "version": 1,
        })
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["non_field_errors"][0]
        self.assertEqual(str(ed), "You need to activate at least one platform")

    def test_profile_default_shard_gt_shard_modulo_error(self):
        artifact, (profile_av,) = force_artifact()
        serializer = ProfileSerializer(data={
            "artifact": str(artifact.pk),
            "source": base64.b64encode(build_mobileconfig_data()),
            "macos": True,
            "shard_modulo": 10,
            "default_shard": 11,
            "version": 1,
        })
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["default_shard"][0]
        self.assertEqual(str(ed), "Must be less than or equal to the shard modulo")

    def test_profile_excluded_tags_confict(self):
        artifact, (profile_av,) = force_artifact()
        tag = Tag.objects.create(name=get_random_string(12))
        serializer = ProfileSerializer(data={
            "artifact": str(artifact.pk),
            "source": base64.b64encode(build_mobileconfig_data()),
            "macos": True,
            "excluded_tags": [tag.pk],
            "tag_shards": [
                {"tag": tag.pk, "shard": 10},
            ],
            "version": 1,
        })
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["excluded_tags"][0]
        self.assertEqual(str(ed), f"Tag {tag} also present in the tag shards")

    def test_profile_tag_shard_gt_shard_modulo_error(self):
        artifact, (profile_av,) = force_artifact()
        tag = Tag.objects.create(name=get_random_string(12))
        serializer = ProfileSerializer(data={
            "artifact": str(artifact.pk),
            "source": base64.b64encode(build_mobileconfig_data()),
            "macos": True,
            "shard_modulo": 10,
            "default_shard": 0,
            "tag_shards": [
                {"tag": tag.pk, "shard": 11},
            ],
            "version": 1,
        })
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["tag_shards"][0]
        self.assertEqual(str(ed), f"Shard for tag {tag} > shard modulo")

    def test_profile_not_a_plist_error(self):
        artifact, (profile_av,) = force_artifact()
        serializer = ProfileSerializer(data={
            "artifact": str(artifact.pk),
            "source": base64.b64encode(b""),
            "macos": True,
            "version": 1,
        })
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["source"][0]
        self.assertEqual(str(ed), "Not a plist")

    def test_profile_ok(self):
        artifact, (profile_av,) = force_artifact()
        serializer = ProfileSerializer(data={
            "artifact": str(artifact.pk),
            "source": base64.b64encode(build_mobileconfig_data()),
            "macos": True,
            "version": 1,
        })
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data["artifact_version"]["artifact"], artifact)
        self.assertEqual(serializer.validated_data["profile"]["payload_identifier"], "com.example.my-profile")
