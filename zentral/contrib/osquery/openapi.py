from zentral.utils.drf_spectacular import register_enum_name_overrides
from .models import Platform


# "platform": one of three distinct choice sets across modules that would
# otherwise collide on the auto-derived name (see also inventory and mdm).
# Platform is a plain enum.Enum whose choices() is a classmethod, so pass the
# callable — drf-spectacular calls it to get the choice set (passing the class
# would expand its raw (name, mask) values instead).
register_enum_name_overrides(
    OsqueryPlatformEnum=Platform.choices,
)
