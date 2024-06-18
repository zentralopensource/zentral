import datetime
from unittest.mock import patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.santa.events import (_build_file_tree_from_santa_event,
                                          _create_bundle_binaries,
                                          _create_missing_bundles,
                                          _update_targets,
                                          EventMetadata,
                                          SantaEnrollmentEvent, SantaEventEvent,
                                          SantaRuleSetUpdateEvent, SantaRuleUpdateEvent)
from zentral.contrib.santa.models import Bundle, Configuration, Target
from .utils import new_sha256


class SantaEventTestCase(TestCase):
    maxDiff = None

    def test_event_with_signed_bundle(self):
        event_d = {
            'current_sessions': [],
            'decision': 'ALLOW_UNKNOWN',
            'executing_user': 'root',
            'execution_time': 2242783327.585212,
            'file_bundle_id': 'servicecontroller:com.apple.stomp.transcoderx',
            'file_bundle_name': 'CompressorTranscoderX',
            'file_bundle_path': ('/Library/Frameworks/Compressor.framework/'
                                 'Versions/A/Resources/CompressorTranscoderX.bundle'),
            'file_bundle_version': '3.5.3',
            'file_bundle_version_string': '3.5.3',
            'file_name': 'compressord',
            'file_path': ('/Library/Frameworks/Compressor.framework/'
                          'Versions/A/Resources/CompressorTranscoderX.bundle/Contents/MacOS'),
            'file_sha256': '700362aec8dee7df2f17de03df0d0844979b0eca7e878f75248c91ae56b1a7c1',
            'logged_in_users': [],
            'parent_name': 'launchd',
            'pid': 95,
            'ppid': 1,
            'quarantine_timestamp': 0,
            'cdhash': '575bc039ebf67a3fd686a14d5d1bc569ec7ba18e',
            'signing_id': 'platform:compressor',
            'signing_chain': [{'cn': 'Software Signing',
                               'org': 'Apple Inc.',
                               'sha256': '47e9216d9e90fa2be9c352d40826c9573055f61188942fff25d58da96f8899d4',
                               'valid_from': 1172268176,
                               'valid_until': 1421272976},
                              {'cn': 'Apple Code Signing Certification Authority',
                               'org': 'Apple Inc.',
                               'ou': 'Apple Certification Authority',
                               'sha256': '3afa0bf5027fd0532f436b39363a680aefd6baf7bf6a4f97f17be2937b84b150',
                               'valid_from': 1171487959,
                               'valid_until': 1423948759},
                              {'cn': 'Apple Root CA',
                               'org': 'Apple Inc.',
                               'ou': 'Apple Certification Authority',
                               'sha256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
                               'valid_from': 1146001236,
                               'valid_until': 2054670036}]
        }
        file_d = {
            'source': {'module': 'zentral.contrib.santa', 'name': 'Santa events'},
            'bundle': {'bundle_id': 'servicecontroller:com.apple.stomp.transcoderx',
                       'bundle_name': 'CompressorTranscoderX',
                       'bundle_version': '3.5.3',
                       'bundle_version_str': '3.5.3'},
            'bundle_path': ('/Library/Frameworks/Compressor.framework/'
                            'Versions/A/Resources/CompressorTranscoderX.bundle'),
            'name': 'compressord',
            'path': ('/Library/Frameworks/Compressor.framework/'
                     'Versions/A/Resources/CompressorTranscoderX.bundle/Contents/MacOS'),
            'sha_256': '700362aec8dee7df2f17de03df0d0844979b0eca7e878f75248c91ae56b1a7c1',
            'cdhash': '575bc039ebf67a3fd686a14d5d1bc569ec7ba18e',
            'signing_id': 'platform:compressor',
            'signed_by': {
                'common_name': 'Software Signing',
                'organization': 'Apple Inc.',
                'organizational_unit': None,
                'sha_256': '47e9216d9e90fa2be9c352d40826c9573055f61188942fff25d58da96f8899d4',
                'valid_from': datetime.datetime(2007, 2, 23, 22, 2, 56),
                'valid_until': datetime.datetime(2015, 1, 14, 22, 2, 56),
                'signed_by': {
                    'common_name': 'Apple Code Signing Certification Authority',
                    'organization': 'Apple Inc.',
                    'organizational_unit': 'Apple Certification Authority',
                    'sha_256': '3afa0bf5027fd0532f436b39363a680aefd6baf7bf6a4f97f17be2937b84b150',
                    'valid_from': datetime.datetime(2007, 2, 14, 21, 19, 19),
                    'valid_until': datetime.datetime(2015, 2, 14, 21, 19, 19),
                    'signed_by': {
                        'common_name': 'Apple Root CA',
                        'organization': 'Apple Inc.',
                        'organizational_unit': 'Apple Certification Authority',
                        'sha_256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
                        'valid_from': datetime.datetime(2006, 4, 25, 21, 40, 36),
                        'valid_until': datetime.datetime(2035, 2, 9, 21, 40, 36),
                    },
                },
             }
        }
        self.assertEqual(_build_file_tree_from_santa_event(event_d), file_d)

    def test_event_with_unsigned_bundle(self):
        event_d = {
            'current_sessions': ['std@console',
                                 'std@ttys000',
                                 'std@ttys001',
                                 'std@ttys002',
                                 'std@ttys003'],
            'decision': 'BLOCK_UNKNOWN',
            'executing_user': 'std',
            'execution_time': 1492004439.58063,
            'file_bundle_id': 'com.googlecode.munki.ManagedSoftwareCenter',
            'file_bundle_name': 'Managed Software Center',
            'file_bundle_path': '/Applications/Managed Software Center.app',
            'file_bundle_version': '2842',
            'file_bundle_version_string': '4.2.2842',
            'file_name': 'Managed Software Center',
            'file_path': '/Applications/Managed Software Center.app/Contents/MacOS',
            'file_sha256': '3bccb77072bbc3eac675e2d95f6ef0f23362f015941dd3175bbc7f2d630040f2',
            'logged_in_users': ['std'],
            'parent_name': 'launchd',
            'pid': 1279,
            'ppid': 1,
            'quarantine_timestamp': 0,
            'signing_chain': []
        }
        file_d = {
            'source': {'module': 'zentral.contrib.santa', 'name': 'Santa events'},
            'bundle': {
                'bundle_id': 'com.googlecode.munki.ManagedSoftwareCenter',
                'bundle_name': 'Managed Software Center',
                'bundle_version': '2842',
                'bundle_version_str': '4.2.2842'
            },
            'bundle_path': '/Applications/Managed Software Center.app',
            'name': 'Managed Software Center',
            'path': '/Applications/Managed Software Center.app/Contents/MacOS',
            'sha_256': '3bccb77072bbc3eac675e2d95f6ef0f23362f015941dd3175bbc7f2d630040f2',
            'cdhash': None,
            'signed_by': None,
            'signing_id': None,
        }
        self.assertEqual(_build_file_tree_from_santa_event(event_d), file_d)

    def test_event_without_bundle(self):
        event_d = {
            'current_sessions': ['std@console',
                                 'std@ttys001',
                                 'std@ttys000',
                                 'std@ttys002'],
            'decision': 'BLOCK_UNKNOWN',
            'executing_user': 'root',
            'execution_time': 1491860971.578268,
            'file_name': 'act',
            'file_path': '/var/tmp/act',
            'file_sha256': '13735e5fba4e11988645f0fa02f8dfa0c6caaf13a1e6c1cf06a47f80a7aab236',
            'logged_in_users': ['std'],
            'parent_name': 'bash',
            'pid': 1593,
            'ppid': 1585,
            'quarantine_timestamp': 0,
            'signing_chain': []
        }
        file_d = {
            'source': {'module': 'zentral.contrib.santa', 'name': 'Santa events'},
            'bundle': None,
            'bundle_path': None,
            'name': 'act',
            'path': '/var/tmp/act',
            'sha_256': '13735e5fba4e11988645f0fa02f8dfa0c6caaf13a1e6c1cf06a47f80a7aab236',
            'cdhash': None,
            'signed_by': None,
            'signing_id': None,
        }
        self.assertEqual(_build_file_tree_from_santa_event(event_d), file_d)

    @staticmethod
    def get_event_with_linked_objects(
        mas_signed=False,
        with_team_id=True,
        with_signing_id=True,
        with_cdhash=True,
        unknown_dev_id_issuer=False,
        flat=False,
        short_chain=False,
    ):
        event_d = {
            'current_sessions': ['personne@console', 'flaco@ttys000'],
            'decision': 'ALLOW_UNKNOWN',
            'executing_user': 'personne',
            'execution_time': 1637562907.2363129,
            'file_bundle_id': 'org.mozilla.firefox',
            'file_bundle_name': 'Firefox',
            'file_bundle_path': '/Applications/Firefox.app',
            'file_bundle_version': '9421.11.3',
            'file_bundle_version_string': '94.0.1',
            'file_name': 'firefox',
            'file_path': '/Applications/Firefox.app/Contents/MacOS',
            'file_sha256': '4bc6526e30f2d22d21dd58c60d401454bb6c772733a59cc1c3a21b52b0a23f57',
            'logged_in_users': ['personne'],
            'parent_name': 'launchd',
            'pid': 1280,
            'ppid': 1,
            'quarantine_agent_bundle_id': 'com.apple.Safari',
            'quarantine_data_url': 'https://download-installer.cdn.mozilla.net/pub/firefox/releases'
                                   '/94.0.1/mac/de/Firefox%2094.0.1.dmg',
            'quarantine_timestamp': 1637562799,
            'signing_chain': []
        }
        if mas_signed:
            event_d['signing_chain'] = [
                {'cn': 'Apple Mac OS Application Signing',
                 'org': 'Apple Inc.',
                 'sha256': '61977d6006459c4cefe9b988a453589946224957bfc07b262cd7ca1b7a61e04e',
                 'valid_from': 1452150602,
                 'valid_until': 1675728000},
                {'cn': 'Apple Worldwide Developer Relations Certification Authority',
                 'org': 'Apple Inc.',
                 'ou': 'Apple Worldwide Developer Relations',
                 'sha256': 'ce057691d730f89ca25e916f7335f4c8a15713dcd273a658c024023f8eb809c2',
                 'valid_from': 1360273727,
                 'valid_until': 1675806527},
                {'cn': 'Apple Root CA',
                 'org': 'Apple Inc.',
                 'ou': 'Apple Certification Authority',
                 'sha256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
                 'valid_from': 1146001236,
                 'valid_until': 2054670036}
            ]
        else:
            if unknown_dev_id_issuer:
                issuer_cn = "UNKNOWN ISSUER"
            else:
                issuer_cn = "Developer ID Certification Authority"
            event_d['signing_chain'] = [
                {'cn': 'Developer ID Application: Mozilla Corporation (43AQ936H96)',
                 'org': 'Mozilla Corporation',
                 'ou': '43AQ936H96',
                 'sha256': '96f18e09d65445985c7df5df74ef152a0bc42e8934175a626180d9700c343e7b',
                 'valid_from': 1494270538,
                 'valid_until': 1652123338},
                {'cn': issuer_cn,
                 'org': 'Apple Inc.',
                 'ou': 'Apple Certification Authority',
                 'sha256': '7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f',
                 'valid_from': 1328134335,
                 'valid_until': 1801519935},
                {'cn': 'Apple Root CA',
                 'org': 'Apple Inc.',
                 'ou': 'Apple Certification Authority',
                 'sha256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
                 'valid_from': 1146001236,
                 'valid_until': 2054670036}
            ]
        if with_team_id:
            event_d['team_id'] = '43AQ936H96'
        if with_signing_id:
            event_d['signing_id'] = "43AQ936H96:org.mozilla.firefox"
        if with_cdhash:
            event_d['cdhash'] = "575bc039ebf67a3fd686a14d5d1bc569ec7ba18e"
        if short_chain:
            event_d["signing_chain"] = event_d.pop("signing_chain")[:1]
        if flat:
            for i, cert in enumerate(event_d.pop('signing_chain')):
                event_d[f"signing_cert_{i}"] = cert
        return SantaEventEvent(EventMetadata(), event_d)

    def test_std_event_without_team_id_known_issuer_linked_objects(self):
        event = self.get_event_with_linked_objects(
            mas_signed=False,
            with_cdhash=False,
            with_signing_id=False,
            with_team_id=False,
            unknown_dev_id_issuer=False
        )
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"file": [("sha256", "4bc6526e30f2d22d21dd58c60d401454bb6c772733a59cc1c3a21b52b0a23f57")],
             "certificate": [("sha256", "96f18e09d65445985c7df5df74ef152a0bc42e8934175a626180d9700c343e7b"),
                             ("sha256", "7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f"),
                             ("sha256", "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024")],
             "apple_team_id": [("43AQ936H96",)]}
        )

    def test_std_event_without_team_id_known_issuer_linked_objects_flat(self):
        event = self.get_event_with_linked_objects(
            mas_signed=False,
            with_cdhash=False,
            with_signing_id=False,
            with_team_id=False,
            unknown_dev_id_issuer=False,
            flat=True
        )
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"file": [("sha256", "4bc6526e30f2d22d21dd58c60d401454bb6c772733a59cc1c3a21b52b0a23f57")],
             "certificate": [("sha256", "96f18e09d65445985c7df5df74ef152a0bc42e8934175a626180d9700c343e7b"),
                             ("sha256", "7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f"),
                             ("sha256", "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024")],
             "apple_team_id": [("43AQ936H96",)]}
        )

    def test_std_event_without_team_id_short_chain(self):
        event = self.get_event_with_linked_objects(
            mas_signed=False,
            with_cdhash=False,
            with_signing_id=False,
            with_team_id=False,
            unknown_dev_id_issuer=False,
            flat=True,
            short_chain=True
        )
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"file": [("sha256", "4bc6526e30f2d22d21dd58c60d401454bb6c772733a59cc1c3a21b52b0a23f57")],
             "certificate": [("sha256", "96f18e09d65445985c7df5df74ef152a0bc42e8934175a626180d9700c343e7b")]}
        )

    def test_std_event_without_team_id_unknown_issuer_linked_objects(self):
        event = self.get_event_with_linked_objects(
            mas_signed=False,
            with_cdhash=False,
            with_signing_id=False,
            with_team_id=False,
            unknown_dev_id_issuer=True
        )
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"file": [("sha256", "4bc6526e30f2d22d21dd58c60d401454bb6c772733a59cc1c3a21b52b0a23f57")],
             "certificate": [("sha256", "96f18e09d65445985c7df5df74ef152a0bc42e8934175a626180d9700c343e7b"),
                             ("sha256", "7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f"),
                             ("sha256", "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024")]}
        )

    def test_std_event_without_team_id_unknown_issuer_linked_objects_flat(self):
        event = self.get_event_with_linked_objects(
            mas_signed=False,
            with_cdhash=False,
            with_signing_id=False,
            with_team_id=False,
            unknown_dev_id_issuer=True,
            flat=True
        )
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"file": [("sha256", "4bc6526e30f2d22d21dd58c60d401454bb6c772733a59cc1c3a21b52b0a23f57")],
             "certificate": [("sha256", "96f18e09d65445985c7df5df74ef152a0bc42e8934175a626180d9700c343e7b"),
                             ("sha256", "7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f"),
                             ("sha256", "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024")]}
        )

    def test_std_event_with_team_id_linked_objects(self):
        event = self.get_event_with_linked_objects(mas_signed=False)
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"file": [("sha256", "4bc6526e30f2d22d21dd58c60d401454bb6c772733a59cc1c3a21b52b0a23f57"),
                      ("cdhash", "575bc039ebf67a3fd686a14d5d1bc569ec7ba18e"),
                      ("apple_signing_id", "43AQ936H96:org.mozilla.firefox")],
             "certificate": [("sha256", "96f18e09d65445985c7df5df74ef152a0bc42e8934175a626180d9700c343e7b"),
                             ("sha256", "7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f"),
                             ("sha256", "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024")],
             "apple_team_id": [("43AQ936H96",)]}
        )

    def test_std_event_with_team_id_linked_objects_flat(self):
        event = self.get_event_with_linked_objects(mas_signed=False, flat=True)
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"file": [("sha256", "4bc6526e30f2d22d21dd58c60d401454bb6c772733a59cc1c3a21b52b0a23f57"),
                      ("cdhash", "575bc039ebf67a3fd686a14d5d1bc569ec7ba18e"),
                      ("apple_signing_id", "43AQ936H96:org.mozilla.firefox")],
             "certificate": [("sha256", "96f18e09d65445985c7df5df74ef152a0bc42e8934175a626180d9700c343e7b"),
                             ("sha256", "7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f"),
                             ("sha256", "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024")],
             "apple_team_id": [("43AQ936H96",)]}
        )

    def test_mas_event_without_team_id_linked_objects(self):
        event = self.get_event_with_linked_objects(
            mas_signed=True,
            with_cdhash=False,
            with_signing_id=False,
            with_team_id=False,
        )
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"file": [("sha256", "4bc6526e30f2d22d21dd58c60d401454bb6c772733a59cc1c3a21b52b0a23f57")],
             "certificate": [("sha256", "61977d6006459c4cefe9b988a453589946224957bfc07b262cd7ca1b7a61e04e"),
                             ("sha256", "ce057691d730f89ca25e916f7335f4c8a15713dcd273a658c024023f8eb809c2"),
                             ("sha256", "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024")]}
        )

    def test_mas_event_without_team_id_linked_objects_flat(self):
        event = self.get_event_with_linked_objects(
            mas_signed=True,
            with_team_id=False,
            flat=True
        )
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"file": [("sha256", "4bc6526e30f2d22d21dd58c60d401454bb6c772733a59cc1c3a21b52b0a23f57"),
                      ("cdhash", "575bc039ebf67a3fd686a14d5d1bc569ec7ba18e"),
                      ("apple_signing_id", "43AQ936H96:org.mozilla.firefox")],

             "certificate": [("sha256", "61977d6006459c4cefe9b988a453589946224957bfc07b262cd7ca1b7a61e04e"),
                             ("sha256", "ce057691d730f89ca25e916f7335f4c8a15713dcd273a658c024023f8eb809c2"),
                             ("sha256", "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024")]}
        )

    def test_mas_event_with_team_id_linked_objects(self):
        event = self.get_event_with_linked_objects(mas_signed=True)
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"file": [("sha256", "4bc6526e30f2d22d21dd58c60d401454bb6c772733a59cc1c3a21b52b0a23f57"),
                      ("cdhash", "575bc039ebf67a3fd686a14d5d1bc569ec7ba18e"),
                      ("apple_signing_id", "43AQ936H96:org.mozilla.firefox")],
             "certificate": [("sha256", "61977d6006459c4cefe9b988a453589946224957bfc07b262cd7ca1b7a61e04e"),
                             ("sha256", "ce057691d730f89ca25e916f7335f4c8a15713dcd273a658c024023f8eb809c2"),
                             ("sha256", "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024")],
             "apple_team_id": [("43AQ936H96",)]}
        )

    def test_mas_event_with_team_id_linked_objects_flat(self):
        event = self.get_event_with_linked_objects(
            mas_signed=True,
            with_cdhash=False,
            with_signing_id=False,
            with_team_id=True,
            flat=True
        )
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"file": [("sha256", "4bc6526e30f2d22d21dd58c60d401454bb6c772733a59cc1c3a21b52b0a23f57")],
             "certificate": [("sha256", "61977d6006459c4cefe9b988a453589946224957bfc07b262cd7ca1b7a61e04e"),
                             ("sha256", "ce057691d730f89ca25e916f7335f4c8a15713dcd273a658c024023f8eb809c2"),
                             ("sha256", "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024")],
             "apple_team_id": [("43AQ936H96",)]}
        )

    def test_binary_rule_update_linked_objects(self):
        event_d = {
            'result': 'updated',
            'rule': {
                'configuration': {'name': 'Default', 'pk': 1},
                'custom_msg': '123',
                'excluded_tags': [{'name': 'untag', 'pk': 1}],
                'policy': 'BLOCKLIST',
                'serial_numbers': ['2345', '456'],
                'tags': [{'name': 'deuxtag', 'pk': 2}],
                'target': {'sha256': 'e699f8aad9c46505531b174f3868ff05de5dddae5d2eef5c3da65a6bac7d2210',
                           'type': 'BINARY'}
            },
            'updates': {'added': {'excluded_tags': [{'name': 'untag', 'pk': 1}],
                                  'serial_numbers': ['456'],
                                  'tags': [{'name': 'deuxtag', 'pk': 2}]},
                        'removed': {'excluded_tags': [{'name': 'deuxtag', 'pk': 2}],
                                    'tags': [{'name': 'untag', 'pk': 1}]}}
        }
        event = SantaRuleUpdateEvent(EventMetadata(), event_d)
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"santa_configuration": [(1,)],
             "file": [("sha256", "e699f8aad9c46505531b174f3868ff05de5dddae5d2eef5c3da65a6bac7d2210")]}
        )

    def test_bundle_rule_update_linked_objects(self):
        event_d = {
            'result': 'updated',
            'rule': {
                'configuration': {'name': 'Default', 'pk': 1},
                'custom_msg': '123',
                'excluded_tags': [{'name': 'untag', 'pk': 1}],
                'policy': 'BLOCKLIST',
                'serial_numbers': ['2345', '456'],
                'tags': [{'name': 'deuxtag', 'pk': 2}],
                'target': {'sha256': 'e699f8aad9c46505531b174f3868ff05de5dddae5d2eef5c3da65a6bac7d2210',
                           'type': 'BUNDLE'}
            },
            'updates': {'added': {'excluded_tags': [{'name': 'untag', 'pk': 1}],
                                  'serial_numbers': ['456'],
                                  'tags': [{'name': 'deuxtag', 'pk': 2}]},
                        'removed': {'excluded_tags': [{'name': 'deuxtag', 'pk': 2}],
                                    'tags': [{'name': 'untag', 'pk': 1}]}}
        }
        event = SantaRuleUpdateEvent(EventMetadata(), event_d)
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"santa_configuration": [(1,)],
             "bundle": [("sha256", "e699f8aad9c46505531b174f3868ff05de5dddae5d2eef5c3da65a6bac7d2210")]}
        )

    def test_cdhash_rule_update_linked_objects(self):
        event_d = {
            'result': 'created',
            'rule': {
                'configuration': {'name': 'Default', 'pk': 1},
                'ruleset': {'name': 'Default', 'pk': 42},
                'custom_msg': '123',
                'excluded_tags': [{'name': 'untag', 'pk': 1}],
                'policy': 'BLOCKLIST',
                'serial_numbers': ['2345', '456'],
                'tags': [{'name': 'deuxtag', 'pk': 2}],
                'target': {'cdhash': '575bc039ebf67a3fd686a14d5d1bc569ec7ba18e',
                           'type': 'CDHASH'}
            }
        }
        event = SantaRuleUpdateEvent(EventMetadata(), event_d)
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"santa_configuration": [(1,)],
             "santa_ruleset": [(42,)],
             "file": [("cdhash", "575bc039ebf67a3fd686a14d5d1bc569ec7ba18e")]}
        )

    def test_certificate_rule_update_linked_objects(self):
        event_d = {
            'result': 'created',
            'rule': {
                'configuration': {'name': 'Default', 'pk': 1},
                'ruleset': {'name': 'Default', 'pk': 42},
                'custom_msg': '123',
                'excluded_tags': [{'name': 'untag', 'pk': 1}],
                'policy': 'BLOCKLIST',
                'serial_numbers': ['2345', '456'],
                'tags': [{'name': 'deuxtag', 'pk': 2}],
                'target': {'sha256': 'e699f8aad9c46505531b174f3868ff05de5dddae5d2eef5c3da65a6bac7d2210',
                           'type': 'CERTIFICATE'}
            }
        }
        event = SantaRuleUpdateEvent(EventMetadata(), event_d)
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"santa_configuration": [(1,)],
             "santa_ruleset": [(42,)],
             "certificate": [("sha256", "e699f8aad9c46505531b174f3868ff05de5dddae5d2eef5c3da65a6bac7d2210")]}
        )

    def test_signing_id_rule_update_linked_objects(self):
        event_d = {
            'result': 'created',
            'rule': {
                'configuration': {'name': 'Default', 'pk': 1},
                'ruleset': {'name': 'Default', 'pk': 42},
                'custom_msg': '123',
                'excluded_tags': [{'name': 'untag', 'pk': 1}],
                'policy': 'BLOCKLIST',
                'serial_numbers': ['2345', '456'],
                'tags': [{'name': 'deuxtag', 'pk': 2}],
                'target': {'signing_id': '43AQ936H96:org.mozilla.firefox',
                           'type': 'SIGNINGID'}
            }
        }
        event = SantaRuleUpdateEvent(EventMetadata(), event_d)
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"santa_configuration": [(1,)],
             "santa_ruleset": [(42,)],
             "file": [("apple_signing_id", "43AQ936H96:org.mozilla.firefox",)]}
        )

    def test_team_id_rule_update_linked_objects(self):
        event_d = {
            'result': 'created',
            'rule': {
                'configuration': {'name': 'Default', 'pk': 1},
                'ruleset': {'name': 'Default', 'pk': 42},
                'custom_msg': '123',
                'excluded_tags': [{'name': 'untag', 'pk': 1}],
                'policy': 'BLOCKLIST',
                'serial_numbers': ['2345', '456'],
                'tags': [{'name': 'deuxtag', 'pk': 2}],
                'target': {'team_id': '43AQ936H96',
                           'type': 'TEAMID'}
            }
        }
        event = SantaRuleUpdateEvent(EventMetadata(), event_d)
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"santa_configuration": [(1,)],
             "santa_ruleset": [(42,)],
             "apple_team_id": [("43AQ936H96",)]}
        )

    def test_ruleset_update_linked_objects(self):
        event_d = {
            'configurations': [
                {'name': 'Default',
                 'pk': 1,
                 'rule_results': {'created': 2,
                                  'deleted': 0,
                                  'present': 0,
                                  'updated': 0}},
                {'name': 'Testing',
                 'pk': 2,
                 'rule_results': {'created': 2,
                                  'deleted': 0,
                                  'present': 0,
                                  'updated': 0}}
            ],
            'result': 'created',
            'ruleset': {'name': 'First ruleset test', 'pk': 43}
        }
        event = SantaRuleSetUpdateEvent(EventMetadata(), event_d)
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"santa_configuration": [(1,), (2,)],
             "santa_ruleset": [(43,)]}
        )

    def test_enrollment_linked_objects(self):
        event_d = {
            "configuration": {"pk": 13, "name": "le temps des cerises"},
            "action": "enrollment"
        }
        event = SantaEnrollmentEvent(EventMetadata(), event_d)
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"santa_configuration": [(13,)]}
        )

    # _update_targets

    @patch("zentral.contrib.santa.events.logger.warning")
    def test_update_targets_unknown_decisiton(self, logger_warning):
        event_d = {"decision": "UNKNOWN!!!"}
        configuration = Configuration.objects.create(name=get_random_string(12))
        self.assertEqual(_update_targets(configuration, [event_d]), {})
        logger_warning.assert_called_once_with("Unknown decision: %s", "UNKNOWN!!!")

    # _create_missing_bundles

    @patch("zentral.contrib.santa.events.logger.error")
    def test_create_missing_bundles_missing_target(self, logger_error):
        event_d = {"decision": "BLOCK_UNKNOWN",
                   "file_bundle_hash": new_sha256()}
        _create_missing_bundles([event_d], {})
        logger_error.assert_called_once_with("Missing BUNDLE target %s", event_d["file_bundle_hash"])

    # _create_bundle_binaries

    @patch("zentral.contrib.santa.events.logger.error")
    def test_create_bundle_binaries_missing_bundle(self, logger_error):
        event_d = {"decision": "BUNDLE_BINARY",
                   "file_bundle_hash": new_sha256()}
        _create_bundle_binaries([event_d])
        self.assertEqual(Bundle.objects.count(), 0)
        logger_error.assert_called_once_with("Unknown bundle: %s", event_d["file_bundle_hash"])

    @patch("zentral.contrib.santa.events.logger.error")
    def test_create_bundle_binaries_bundle_already_uploaded(self, logger_error):
        event_d = {"decision": "BUNDLE_BINARY",
                   "file_bundle_hash": new_sha256(),
                   "file_bundle_binary_count": 42}
        t = Target.objects.create(type=Target.BUNDLE,
                                  identifier=event_d["file_bundle_hash"])
        Bundle.objects.create(
            target=t,
            binary_count=event_d["file_bundle_binary_count"],
            uploaded_at=datetime.datetime.utcnow()
        )
        _create_bundle_binaries([event_d])
        logger_error.assert_called_once_with("Bundle %s already uploaded", event_d["file_bundle_hash"])

    def test_create_bundle_binaries_bundle_without_binary_count(self):
        binary_target = Target.objects.create(type=Target.BINARY, identifier=new_sha256())
        event_d = {"decision": "BUNDLE_BINARY",
                   "file_bundle_hash": new_sha256(),
                   "file_bundle_binary_count": 1,
                   "file_sha256": binary_target.identifier}
        bundle_target = Target.objects.create(type=Target.BUNDLE,
                                              identifier=event_d["file_bundle_hash"])
        b = Bundle.objects.create(
            target=bundle_target,
            binary_count=0,
        )
        self.assertEqual(b.binary_targets.count(), 0)
        _create_bundle_binaries([event_d])
        self.assertEqual(set(b.binary_targets.all()), set([binary_target]))
        b.refresh_from_db()
        self.assertIsNotNone(b.uploaded_at)

    @patch("zentral.contrib.santa.events.logger.error")
    def test_create_bundle_wrong_binary_target_number(self, logger_error):
        binary_target = Target.objects.create(type=Target.BINARY, identifier=new_sha256())
        event_d = {"decision": "BUNDLE_BINARY",
                   "file_bundle_hash": new_sha256(),
                   "file_bundle_binary_count": 1,
                   "file_sha256": binary_target.identifier}
        bundle_target = Target.objects.create(type=Target.BUNDLE,
                                              identifier=event_d["file_bundle_hash"])
        b = Bundle.objects.create(
            target=bundle_target,
            binary_count=event_d["file_bundle_binary_count"],
        )
        extra_target = Target.objects.create(type=Target.BINARY, identifier=new_sha256())
        b.binary_targets.add(extra_target)
        self.assertEqual(b.binary_targets.count(), 1)
        _create_bundle_binaries([event_d])
        self.assertEqual(b.binary_targets.count(), 2)
        logger_error.assert_called_once_with("Bundle %s as wrong number of binary targets",
                                             event_d["file_bundle_hash"])
