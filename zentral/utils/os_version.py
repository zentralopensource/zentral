from itertools import zip_longest
import logging


logger = logging.getLogger("zentral.utils.os_version")


def make_comparable_os_version(os_version):
    default = (0, 0, 0)
    try:
        os_version, supplemental_os_version_extra = os_version.split()
    except AttributeError:
        return default
    except ValueError:
        pass
    else:
        supplemental_os_version_extra = supplemental_os_version_extra.strip("()")
        if supplemental_os_version_extra:
            default = (0, 0, 0, supplemental_os_version_extra)
    try:
        return tuple(
            i or j for i, j in zip_longest(
              (int(i) for i in os_version.split(".")),
              default
            )
        )
    except Exception:
        logger.warning("Cannot parse OS version %s", os_version)
        return (0, 0, 0)
