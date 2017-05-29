import datetime
from django.test import TestCase
from zentral.contrib.santa.events import build_collected_app_tree_from_santa_event


class SantaEventTestCase(TestCase):
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
        app_d = {
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
        self.assertEqual(build_collected_app_tree_from_santa_event(event_d), app_d)

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
        app_d = {
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
            'signed_by': None
        }
        self.assertEqual(build_collected_app_tree_from_santa_event(event_d), app_d)

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
        app_d = {
            'bundle': None,
            'bundle_path': None,
            'name': 'act',
            'path': '/var/tmp/act',
            'sha_256': '13735e5fba4e11988645f0fa02f8dfa0c6caaf13a1e6c1cf06a47f80a7aab236',
            'signed_by': None
        }
        self.assertEqual(build_collected_app_tree_from_santa_event(event_d), app_d)
