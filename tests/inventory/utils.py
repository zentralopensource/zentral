from datetime import datetime
import uuid
from django.utils.crypto import get_random_string
from zentral.core.compliance_checks.models import ComplianceCheck
from zentral.contrib.inventory.compliance_checks import InventoryJMESPathCheck
from zentral.contrib.inventory.models import JMESPathCheck, MachineSnapshotCommit


class MockMetaMachine(object):
    def __init__(self, meta_business_unit_id_set, tag_id_set, platform, type, serial_number="YO"):
        self.meta_business_unit_id_set = set(meta_business_unit_id_set)
        self._tag_id_set = set(tag_id_set)
        self.platform = platform
        self.type = type
        self.serial_number = serial_number
        self.has_deb_packages = platform == "LINUX"

    def get_probe_filtering_values(self):
        return self.platform, self.type, self.meta_business_unit_id_set, self._tag_id_set

    @property
    def cached_probe_filtering_values(self):
        return self.get_probe_filtering_values()


def force_jmespath_check(source_name="Yolo", profile_uuid=None, jmespath_expression=None, tags=None, platforms=None):
    if profile_uuid is None:
        profile_uuid = str(uuid.uuid4())
    if jmespath_expression is None:
        jmespath_expression = f"contains(profiles[*].uuid, `{profile_uuid}`)"
    cc = ComplianceCheck.objects.create(
        name=get_random_string(12),
        model=InventoryJMESPathCheck.get_model(),
    )
    if platforms is None:
        platforms = ["MACOS"]
    jmespath_check = JMESPathCheck.objects.create(
        compliance_check=cc,
        source_name=source_name,
        platforms=platforms,
        jmespath_expression=jmespath_expression
    )
    if tags is not None:
        jmespath_check.tags.set(tags)
    return jmespath_check


def create_ms(computer_name=None):
    if computer_name is None:
        computer_name = get_random_string(12)
    MS_TREE_SOURCE = {"module": "tests.zentral.io", "name": "Zentral Tests"}
    MS_TREE = {
        "source": MS_TREE_SOURCE,
        "business_unit": {"name": "yo bu",
                          "reference": "bu1",
                          "source": MS_TREE_SOURCE,
                          "links": [{"anchor_text": "bu link",
                                     "url": "http://bu-link.de"}]},
        "groups": [{"name": "yo grp",
                    "reference": "grp1",
                    "source": MS_TREE_SOURCE,
                    "links": [{"anchor_text": "group link",
                               "url": "http://group-link.de"}]}],
        "serial_number": "0123456789",
        "system_info": {"computer_name": computer_name},
        "os_version": {'name': 'OS X', 'major': 10, 'minor': 11, 'patch': 1},
        "android_apps": [
            {"display_name": "AndroidApp1",
             "version_name": "1.1"},
            {"display_name": "AndroidApp2",
             "version_name": "1.2"}
        ],
        "deb_packages": [
            {"name": "deb_package_1", "version": "1.1"},
            {"name": "deb_package_2", "version": "1.2"},
        ],
        "ios_apps": [
            {"name": "2Password",
             "version": "1.1"},
            {"name": "3Password",
             "version": "1.2"}
        ],
        "osx_app_instances": [
            {'app': {'bundle_id': 'io.zentral.baller',
                     'bundle_name': 'Baller.app',
                     'bundle_version': '123',
                     'bundle_version_str': '1.2.3'},
             'bundle_path': "/Applications/Baller.app",
             'signed_by': {
                 "common_name": "Developer ID Application: GODZILLA",
                 "organization": "GOZILLA INC",
                 "organizational_unit": "ATOM",
                 "sha_1": 40 * "a",
                 "sha_256": 64 * "a",
                 "valid_from": datetime(2015, 1, 1),
                 "valid_until": datetime(2026, 1, 1),
                 "signed_by": {
                     "common_name": "Developer ID Certification Authority",
                     "organization": "Apple Inc.",
                     "organizational_unit": "Apple Certification Authority",
                     "sha_1": "3b166c3b7dc4b751c9fe2afab9135641e388e186",
                     "sha_256": "7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f",
                     "valid_from": datetime(2012, 12, 1),
                     "valid_until": datetime(2027, 12, 1),
                     "signed_by": {
                         "common_name": "Apple Root CA",
                         "organization": "Apple Inc.",
                         "organizational_unit": "Apple Certification Authority",
                         "sha_1": "611e5b662c593a08ff58d14ae22452d198df6c60",
                         "sha_256": "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
                         "valid_from": datetime(2006, 4, 25),
                         "valid_until": datetime(2035, 2, 9)
                     }
                 }
             }}
        ],
        'profiles': [
            {'display_name': 'Zentral - FileVault configuration',
             'encrypted': False,
             'has_removal_passcode': False,
             'identifier': 'com.zentral.mdm.fv',
             'payloads': [{'identifier': 'com.zentral.mdm.fv.escrow',
                           'type': 'com.apple.security.FDERecoveryKeyEscrow',
                           'uuid': '6cc2b5a5-d48c-46cf-9f08-59207b9b61f3'},
                          {'identifier': 'com.zentral.mdm.fv.options',
                           'type': 'com.apple.MCX',
                           'uuid': 'dcddb0ec-5429-4148-9054-ad49f12256e7'},
                          {'identifier': 'com.zentral.mdm.fv.configuration',
                           'type': 'com.apple.MCX.FileVault2',
                           'uuid': '3bac4ab2-835b-4786-a538-a36ba8175e32'},
                          {'identifier': 'com.zentral.mdm.fv.certificate',
                           'type': 'com.apple.security.pkcs1',
                           'uuid': '5328b541-893e-4a5d-bb91-84900062fd9f'}],
             'removal_disallowed': False,
             'signed_by': {'common_name': 'yolo.example.com',
                           'sha_1': '1111111111111111111111111111111111111111',
                           'signed_by': {'common_name': 'E5',
                                         'organization': "Let's Encrypt",
                                         'sha_1': '5f28d9c589ee4bf31a11b78c72b8d13f079ddc45',
                                         'valid_from': '2024-03-13T00:00:00',
                                         'valid_until': '2027-03-12T23:59:59'},
                           'valid_from': '2024-06-01T13:29:01',
                           'valid_until': '2024-09-01T13:29:00'},
             'uuid': '0b0d3f67-977d-4d3f-bfc8-0db5fdf6c391',
             'verified': True}
        ],
        "program_instances": [
            {"program": {"name": "program_1", "version": "1.1"},
             "install_source": "tests"},
            {"program": {"name": "program_2", "version": "1.2"},
             "install_source": "tests"},
        ],
    }
    _, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(MS_TREE)
    return ms
