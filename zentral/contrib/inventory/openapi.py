from zentral.utils.drf_spectacular import register_enum_name_overrides
from .conf import PLATFORM_CHOICES


# "platform"/"platforms": one of three distinct choice sets across modules that
# would otherwise collide on the auto-derived name (see also osquery and mdm).
register_enum_name_overrides(
    InventoryPlatformEnum=PLATFORM_CHOICES,
)
