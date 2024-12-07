from datetime import datetime, timedelta
from unittest.mock import patch, Mock
import uuid
from django.test import TestCase
from zentral.contrib.mdm.declarations import (artifact_pk_from_identifier_and_model,
                                              get_artifact_identifier,
                                              get_artifact_version_server_token)
from zentral.contrib.mdm.models import Artifact, Declaration


class MDMDeclarationUtilsTestCase(TestCase):
    def test_get_artifact_identifier_not_a_declaration(self):
        with self.assertRaises(ValueError) as cm:
            get_artifact_identifier({"type": Artifact.Type.ENTERPRISE_APP})
        self.assertEqual(cm.exception.args[0], "Artifact is not a declaration")

    def test_artifact_pk_from_identifier_and_model_unknown_path(self):
        with self.assertRaises(ValueError) as cm:
            artifact_pk_from_identifier_and_model("zentral.yolo.00000000-0000-0000-0000-000000000000", Declaration)
        self.assertEqual(cm.exception.args[0], "Unknown artifact identifier path")

    def test_artifact_pk_from_identifier_and_model_invalid_model(self):
        with self.assertRaises(ValueError) as cm:
            artifact_pk_from_identifier_and_model("zentral.data-asset.00000000-0000-0000-0000-000000000000",
                                                  Declaration)
        self.assertEqual(cm.exception.args[0], "Invalid artifact identifier model")

    def test_get_artifact_version_server_token_reinstall_major(self):
        target = Mock()
        target.comparable_os_version = (15, 2, 1)
        av_pk = str(uuid.uuid4())
        server_token = get_artifact_version_server_token(
            target,
            {"reinstall_on_os_update": str(Artifact.ReinstallOnOSUpdate.MAJOR),
             "reinstall_interval": 0},
            {"pk": av_pk}
        )
        self.assertEqual(server_token, f"{av_pk}.ov-15")

    def test_get_artifact_version_server_token_reinstall_minor(self):
        target = Mock()
        target.comparable_os_version = (15, 2, 1)
        av_pk = str(uuid.uuid4())
        server_token = get_artifact_version_server_token(
            target,
            {"reinstall_on_os_update": str(Artifact.ReinstallOnOSUpdate.MINOR),
             "reinstall_interval": 0},
            {"pk": av_pk}
        )
        self.assertEqual(server_token, f"{av_pk}.ov-15.2")

    def test_get_artifact_version_server_token_reinstall_patch(self):
        target = Mock()
        target.comparable_os_version = (15, 2, 1)
        av_pk = str(uuid.uuid4())
        server_token = get_artifact_version_server_token(
            target,
            {"reinstall_on_os_update": str(Artifact.ReinstallOnOSUpdate.PATCH),
             "reinstall_interval": 0},
            {"pk": av_pk}
        )
        self.assertEqual(server_token, f"{av_pk}.ov-15.2.1")

    @patch("zentral.contrib.mdm.declarations.utils.datetime")
    def test_get_artifact_version_server_token_reinstall_interval(self, patched_datetime):
        now = datetime(2025, 1, 1, 0, 0, 0)
        patched_datetime.utcnow.return_value = now
        target = Mock()
        target.comparable_os_version = (15, 2, 1)
        target.target.created_at = now - timedelta(seconds=3600 * 24 * 91)
        av_pk = str(uuid.uuid4())
        server_token = get_artifact_version_server_token(
            target,
            {"reinstall_on_os_update": str(Artifact.ReinstallOnOSUpdate.NO),
             "reinstall_interval": 3600 * 24 * 90},
            {"pk": av_pk}
        )
        self.assertEqual(server_token, f"{av_pk}.ri-1")
