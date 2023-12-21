import uuid
from django.utils.crypto import get_random_string
from zentral.core.compliance_checks.models import ComplianceCheck
from zentral.contrib.inventory.compliance_checks import InventoryJMESPathCheck
from zentral.contrib.inventory.models import JMESPathCheck


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
