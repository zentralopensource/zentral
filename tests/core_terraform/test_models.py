import secrets
from django.test import TestCase
from accounts.models import User
from zentral.core.terraform.models import StateVersion
from .utils import force_state, force_state_version


class TerraformBackendModelsTestCase(TestCase):

    # State

    def test_state_str(self):
        state = force_state()
        self.assertEqual(str(state), state.slug)

    def test_state_get_created_by_display_created_by_username(self):
        state = force_state()
        self.assertEqual(state.get_created_by_display(), state.created_by_username)

    def test_state_get_created_by_display_created_by(self):
        user = User.objects.create_user("yolo", "fomo@zentral.com")
        state = force_state(created_by=user)
        self.assertEqual(state.get_created_by_display(), "fomo@zentral.com")

    # StateVersion

    def test_state_version_str(self):
        state_version = force_state_version()
        self.assertEqual(
            str(state_version),
            state_version.state.slug + " - " + str(state_version.created_at)
        )

    def test_state_version_get_created_by_display_created_by_username(self):
        state_version = force_state_version()
        self.assertEqual(state_version.get_created_by_display(), state_version.created_by_username)

    def test_state_version_get_created_by_display_created_by(self):
        user = User.objects.create_user("yolo", "fomo@zentral.com")
        state_version = force_state_version(created_by=user)
        self.assertEqual(state_version.get_created_by_display(), "fomo@zentral.com")

    def test_state_version_set_encryption_key_error(self):
        state_version = StateVersion(state=force_state(), created_by_username="yolo")
        with self.assertRaises(ValueError) as cm:
            state_version.set_encryption_key(b"123")
        self.assertEqual(cm.exception.args[0], "StateVersion must have a pk")

    def test_state_version_encryption_key(self):
        state_version = StateVersion.objects.create(state=force_state(), created_by_username="yolo")
        key = secrets.token_bytes()
        state_version.set_encryption_key(key)
        self.assertEqual(state_version.get_encryption_key(), key)

    def test_state_version_rewrap_secrets(self):
        state_version = StateVersion.objects.create(state=force_state(), created_by_username="yolo")
        key = secrets.token_bytes()
        state_version.set_encryption_key(key)
        state_version.rewrap_secrets()
        self.assertEqual(state_version.get_encryption_key(), key)

    # Lock

    def test_lock_str(self):
        state = force_state(locked=True)
        self.assertEqual(str(state.lock), state.lock.uid)
