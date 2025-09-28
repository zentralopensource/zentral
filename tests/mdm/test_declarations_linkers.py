from unittest.mock import patch
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.declarations import _find_zentral_ref_artifact, declaration_linkers, get_declaration_info
from zentral.contrib.mdm.models import Artifact, Channel, Platform
from .utils import force_artifact


class MDMDeclarationLinkersTestCase(TestCase):
    def test_declaration_linkers_load(self):
        self.assertEqual(len(declaration_linkers), 42)

    def test_activation_simple_refs(self):
        linker = declaration_linkers["com.apple.activation.simple"]
        self.assertEqual(linker.type, "com.apple.activation.simple")
        self.assertEqual(
            linker.refs,
            {('StandardConfigurations', '*'): ['com.apple.configuration.*']}
        )

    def test_account_mail_refs(self):
        linker = declaration_linkers["com.apple.configuration.account.mail"]
        self.assertEqual(linker.type, "com.apple.configuration.account.mail")
        self.assertEqual(
            linker.refs,
            {('UserIdentityAssetReference',): ['com.apple.asset.useridentity'],
             ('IncomingServer',
              'AuthenticationCredentialsAssetReference'): ['com.apple.asset.credential.userpassword'],
             ('OutgoingServer',
              'AuthenticationCredentialsAssetReference'): ['com.apple.asset.credential.userpassword'],
             ('SMIME', 'Signing', 'IdentityAssetReference'): ['com.apple.asset.credential.acme',
                                                              'com.apple.asset.credential.identity',
                                                              'com.apple.asset.credential.scep'],
             ('SMIME', 'Encryption', 'IdentityAssetReference'): ['com.apple.asset.credential.acme',
                                                                 'com.apple.asset.credential.identity',
                                                                 'com.apple.asset.credential.scep']}
        )

    def test_substitute_refs_dict(self):
        linker = declaration_linkers["com.apple.configuration.services.configuration-files"]
        payload = linker.substitute_refs({"DataAssetReference": "yolo"}, {("DataAssetReference",): "fomo"})
        self.assertEqual(payload, {"DataAssetReference": "fomo"})

    def test_substitute_refs_list(self):
        linker = declaration_linkers["com.apple.activation.simple"]
        payload = linker.substitute_refs({"StandardConfigurations": ["yolo", "fomo"]},
                                         {("StandardConfigurations", "1"): "fomo2",
                                          ("StandardConfigurations", "0"): "yolo2"})
        self.assertEqual(payload, {"StandardConfigurations": ["yolo2", "fomo2"]})

    # get_declaration_info

    def test_get_declaration_info_invalid_source(self):
        with self.assertRaises(ValueError) as cm:
            get_declaration_info("", Channel.DEVICE, [Platform.MACOS])
        self.assertEqual(cm.exception.args[0], "Invalid JSON data")

    def test_get_declaration_info_not_a_dict(self):
        with self.assertRaises(ValueError) as cm:
            get_declaration_info("1", Channel.DEVICE, [Platform.MACOS])
        self.assertEqual(cm.exception.args[0], "Declaration is not a dictionary")

    def test_get_declaration_info_missing_identifier(self):
        with self.assertRaises(ValueError) as cm:
            get_declaration_info("{}", Channel.DEVICE, [Platform.MACOS])
        self.assertEqual(cm.exception.args[0], "Missing Identifier")

    def test_get_declaration_info_invalid_identifier_not_a_str(self):
        with self.assertRaises(ValueError) as cm:
            get_declaration_info('{"Identifier": 1}', Channel.DEVICE, [Platform.MACOS])
        self.assertEqual(cm.exception.args[0], "Invalid Identifier")

    def test_get_declaration_info_invalid_identifier_too_short(self):
        with self.assertRaises(ValueError) as cm:
            get_declaration_info('{"Identifier": ""}', Channel.DEVICE, [Platform.MACOS])
        self.assertEqual(cm.exception.args[0], "Invalid Identifier")

    def test_get_declaration_info_missing_server_token(self):
        with self.assertRaises(ValueError) as cm:
            get_declaration_info('{"Identifier": "123"}', Channel.DEVICE, [Platform.MACOS])
        self.assertEqual(cm.exception.args[0], "Missing ServerToken")

    def test_get_declaration_info_invalid_server_token_not_a_str(self):
        with self.assertRaises(ValueError) as cm:
            get_declaration_info('{"Identifier": "123", "ServerToken": 1}', Channel.DEVICE, [Platform.MACOS])
        self.assertEqual(cm.exception.args[0], "Invalid ServerToken")

    def test_get_declaration_info_invalid_server_token_too_short(self):
        with self.assertRaises(ValueError) as cm:
            get_declaration_info('{"Identifier": "123", "ServerToken": ""}', Channel.DEVICE, [Platform.MACOS])
        self.assertEqual(cm.exception.args[0], "Invalid ServerToken")

    def test_get_declaration_info_missing_type(self):
        with self.assertRaises(ValueError) as cm:
            get_declaration_info('{"Identifier": "123", "ServerToken": "456"}', Channel.DEVICE, [Platform.MACOS])
        self.assertEqual(cm.exception.args[0], "Missing Type")

    def test_get_declaration_info_unknown_type(self):
        with self.assertRaises(ValueError) as cm:
            get_declaration_info('{"Identifier": "123", "ServerToken": "456", "Type": "a"}',
                                 Channel.DEVICE, [Platform.MACOS])
        self.assertEqual(cm.exception.args[0], "Unknown Type")

    def test_get_declaration_info_missing_payload(self):
        with self.assertRaises(ValueError) as cm:
            get_declaration_info(
                '{"Identifier": "123",'
                ' "ServerToken": "456",'
                '  "Type": "com.apple.asset.data"}',
                Channel.DEVICE, [Platform.MACOS]
            )
        self.assertEqual(cm.exception.args[0], "Missing Payload")

    def test_get_declaration_info_payload_not_a_dict(self):
        with self.assertRaises(ValueError) as cm:
            get_declaration_info(
                '{"Identifier": "123",'
                ' "ServerToken": "456",'
                '  "Type": "com.apple.asset.data",'
                '  "Payload": 1}',
                Channel.DEVICE, [Platform.MACOS]
            )
        self.assertEqual(cm.exception.args[0], "Payload is not a dictionary")

    def test_get_declaration_info_no_refs(self):
        info = get_declaration_info(
            '{"Identifier": "123",'
            ' "ServerToken": "456",'
            ' "Type": "com.apple.asset.data",'
            ' "Payload": {}}',
            Channel.DEVICE, [Platform.MACOS]
        )
        self.assertEqual(
            info,
            {'identifier': '123',
             'payload': {},
             'refs': {},
             'server_token': '456',
             'type': 'com.apple.asset.data'}
        )

    def test_get_declaration_info_no_refs_ensure_server_token(self):
        info = get_declaration_info(
            '{"Identifier": "123",'
            # no ServerToken
            ' "Type": "com.apple.asset.data",'
            ' "Payload": {}}',
            Channel.DEVICE, [Platform.MACOS],
            ensure_server_token=True,
        )
        server_token = info.pop("server_token")
        self.assertTrue(isinstance(server_token, str))
        self.assertEqual(
            info,
            {'identifier': '123',
             'payload': {},
             'refs': {},
             'type': 'com.apple.asset.data'}
        )

    def test_get_declaration_ztl_ref_configuration(self):
        artifact, _ = force_artifact(
            artifact_type=Artifact.Type.MANUAL_CONFIGURATION,
        )
        info = get_declaration_info(
            '{"Identifier": "123",'
            ' "ServerToken": "456",'
            ' "Type": "com.apple.activation.simple",'
            ' "Payload": {'
            f'   "StandardConfigurations": ["ztl:{artifact.pk}"]'
            ' }}',
            Channel.DEVICE, [Platform.MACOS]
        )
        self.assertEqual(
            info,
            {'identifier': '123',
             'payload': {
                 'StandardConfigurations': [f'ztl:{artifact.pk}'],
             },
             'refs': {("StandardConfigurations", "0"): artifact},
             'server_token': "456",
             'type': 'com.apple.activation.simple'}
        )

    def test_get_declaration_ztl_ref_asset(self):
        artifact, _ = force_artifact(
            artifact_type=Artifact.Type.ASSET,
            decl_type="com.apple.asset.data",
        )
        info = get_declaration_info(
            '{"Identifier": "123",'
            ' "ServerToken": "456",'
            ' "Type": "com.apple.configuration.services.configuration-files",'
            ' "Payload": {'
            '    "ServiceType": "com.apple.sudo",'
            f'   "DataAssetReference": "ztl:{artifact.pk}"'
            ' }}',
            Channel.DEVICE, [Platform.MACOS]
        )
        self.assertEqual(
            info,
            {'identifier': '123',
             'payload': {
                 'ServiceType': 'com.apple.sudo',
                 'DataAssetReference': f'ztl:{artifact.pk}',
             },
             'refs': {("DataAssetReference",): artifact},
             'server_token': "456",
             'type': 'com.apple.configuration.services.configuration-files'}
        )

    def test_get_declaration_ztl_ref_data_asset(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        info = get_declaration_info(
            '{"Identifier": "123",'
            ' "ServerToken": "456",'
            ' "Type": "com.apple.configuration.services.configuration-files",'
            ' "Payload": {'
            '    "ServiceType": "com.apple.sudo",'
            f'   "DataAssetReference": "ztl:{artifact.pk}"'
            ' }}',
            Channel.DEVICE, [Platform.MACOS]
        )
        self.assertEqual(
            info,
            {'identifier': '123',
             'payload': {
                 'ServiceType': 'com.apple.sudo',
                 'DataAssetReference': f'ztl:{artifact.pk}',
             },
             'refs': {("DataAssetReference",): artifact},
             'server_token': "456",
             'type': 'com.apple.configuration.services.configuration-files'}
        )

    def test_get_declaration_ztl_ref_unknown(self):
        artifact_pk = str(uuid.uuid4())
        with self.assertRaises(ValueError) as cm:
            get_declaration_info(
                '{"Identifier": "123",'
                ' "ServerToken": "456",'
                ' "Type": "com.apple.configuration.services.configuration-files",'
                ' "Payload": {'
                '    "ServiceType": "com.apple.sudo",'
                f'   "DataAssetReference": "ztl:{artifact_pk}"'
                ' }}',
                Channel.DEVICE, [Platform.MACOS]
            )
        self.assertEqual(cm.exception.args[0], f"Unknown zentral artifact: {artifact_pk}")

    def test_get_declaration_ztl_ref_not_a_declaration(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        with self.assertRaises(ValueError) as cm:
            get_declaration_info(
                '{"Identifier": "123",'
                ' "ServerToken": "456",'
                ' "Type": "com.apple.configuration.services.configuration-files",'
                ' "Payload": {'
                '    "ServiceType": "com.apple.sudo",'
                f'   "DataAssetReference": "ztl:{artifact.pk}"'
                ' }}',
                Channel.DEVICE, [Platform.MACOS]
            )
        self.assertEqual(cm.exception.args[0], f"Zentral artifact is not a declaration: {artifact.pk}")

    @patch("zentral.contrib.mdm.declarations.linkers.logger.error")
    def test_find_zentral_ref_artifact_unknown_asset_artifact_type(self, logger_error):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.ASSET)
        with self.assertRaises(ValueError) as cm:
            _find_zentral_ref_artifact(f"ztl:{artifact.pk}", ["com.apple.asset.does_not_exist"])
        self.assertEqual(cm.exception.args[0], f"Incompatible zentral artifact: {artifact.pk}")
        logger_error.assert_called_once_with("Unknown asset artifact type %s", "com.apple.asset.does_not_exist")

    @patch("zentral.contrib.mdm.declarations.linkers.logger.error")
    def test_find_zentral_ref_artifact_unknown_artifact_type(self, logger_error):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.ASSET)
        with self.assertRaises(ValueError) as cm:
            _find_zentral_ref_artifact(f"ztl:{artifact.pk}", ["com.apple.does_not_exist"])
        self.assertEqual(cm.exception.args[0], f"Incompatible zentral artifact: {artifact.pk}")
        logger_error.assert_called_once_with("Unknown artifact type %s", "com.apple.does_not_exist")

    def test_get_declaration_ztl_ref_incompatible(self):
        artifact, _ = force_artifact(
            artifact_type=Artifact.Type.MANUAL_CONFIGURATION,
        )
        with self.assertRaises(ValueError) as cm:
            get_declaration_info(
                '{"Identifier": "123",'
                ' "ServerToken": "456",'
                ' "Type": "com.apple.configuration.services.configuration-files",'
                ' "Payload": {'
                '    "ServiceType": "com.apple.sudo",'
                f'   "DataAssetReference": "ztl:{artifact.pk}"'
                ' }}',
                Channel.DEVICE, [Platform.MACOS]
            )
        self.assertEqual(cm.exception.args[0], f"Incompatible zentral artifact: {artifact.pk}")

    def test_get_declaration_custom_ref_type_match(self):
        identifier = get_random_string(12)
        artifact, _ = force_artifact(
            artifact_type=Artifact.Type.ASSET,
            decl_identifier=identifier,
            decl_type="com.apple.asset.data",
        )
        info = get_declaration_info(
            '{"Identifier": "123",'
            ' "ServerToken": "456",'
            ' "Type": "com.apple.configuration.services.configuration-files",'
            ' "Payload": {'
            '    "ServiceType": "com.apple.sudo",'
            f'   "DataAssetReference": "{identifier}"'
            ' }}',
            Channel.DEVICE, [Platform.MACOS]
        )
        self.assertEqual(
            info,
            {'identifier': '123',
             'payload': {
                 'ServiceType': 'com.apple.sudo',
                 'DataAssetReference': identifier,
             },
             'refs': {("DataAssetReference",): artifact},
             'server_token': "456",
             'type': 'com.apple.configuration.services.configuration-files'}
        )

    def test_get_declaration_custom_ref_type_prefix_match(self):
        identifier = get_random_string(12)
        artifact, _ = force_artifact(
            artifact_type=Artifact.Type.MANUAL_CONFIGURATION,
            decl_identifier=identifier,
        )
        info = get_declaration_info(
            '{"Identifier": "123",'
            ' "ServerToken": "456",'
            ' "Type": "com.apple.activation.simple",'
            ' "Payload": {'
            f'   "StandardConfigurations": ["{identifier}"]'
            ' }}',
            Channel.DEVICE, [Platform.MACOS]
        )
        self.assertEqual(
            info,
            {'identifier': '123',
             'payload': {
                 'StandardConfigurations': [identifier],
             },
             'refs': {("StandardConfigurations", "0"): artifact},
             'server_token': "456",
             'type': 'com.apple.activation.simple'}
        )

    def test_get_declaration_custom_ref_unknown(self):
        identifier = get_random_string(12)
        with self.assertRaises(ValueError) as cm:
            get_declaration_info(
                '{"Identifier": "123",'
                ' "ServerToken": "456",'
                ' "Type": "com.apple.configuration.services.configuration-files",'
                ' "Payload": {'
                '    "ServiceType": "com.apple.sudo",'
                f'   "DataAssetReference": "{identifier}"'
                ' }}',
                Channel.DEVICE, [Platform.MACOS]
            )
        self.assertEqual(cm.exception.args[0], f"Unknown custom artifact: {identifier}")

    def test_get_declaration_custom_ref_incompatible(self):
        identifier = get_random_string(12)
        artifact, _ = force_artifact(
            artifact_type=Artifact.Type.ASSET,
            decl_identifier=identifier,
            decl_type="com.apple.asset.credential.userpassword",
        )
        with self.assertRaises(ValueError) as cm:
            get_declaration_info(
                '{"Identifier": "123",'
                ' "ServerToken": "456",'
                ' "Type": "com.apple.configuration.services.configuration-files",'
                ' "Payload": {'
                '    "ServiceType": "com.apple.sudo",'
                f'   "DataAssetReference": "{identifier}"'
                ' }}',
                Channel.DEVICE, [Platform.MACOS]
            )
        self.assertEqual(cm.exception.args[0], f"Incompatible custom artifact: {identifier}")

    def test_get_declaration_custom_ref_bad_channel(self):
        identifier = get_random_string(12)
        artifact, _ = force_artifact(
            artifact_type=Artifact.Type.MANUAL_CONFIGURATION,
            channel=Channel.USER,
            decl_identifier=identifier,
        )
        with self.assertRaises(ValueError) as cm:
            get_declaration_info(
                '{"Identifier": "123",'
                ' "ServerToken": "456",'
                ' "Type": "com.apple.activation.simple",'
                ' "Payload": {'
                f'   "StandardConfigurations": ["{identifier}"]'
                ' }}',
                Channel.DEVICE, [Platform.MACOS]
            )
        self.assertEqual(cm.exception.args[0], f"Referenced artifact {identifier} on a different channel.")

    def test_get_declaration_custom_ref_bad_platforms(self):
        identifier = get_random_string(12)
        artifact, _ = force_artifact(
            artifact_type=Artifact.Type.MANUAL_CONFIGURATION,
            decl_identifier=identifier,
        )
        with self.assertRaises(ValueError) as cm:
            get_declaration_info(
                '{"Identifier": "123",'
                ' "ServerToken": "456",'
                ' "Type": "com.apple.activation.simple",'
                ' "Payload": {'
                f'   "StandardConfigurations": ["{identifier}"]'
                ' }}',
                Channel.DEVICE, [Platform.MACOS, Platform.IOS]
            )
        self.assertEqual(cm.exception.args[0], f"Referenced artifact {identifier} not available for all platforms.")
