from itertools import zip_longest
import logging


logger = logging.getLogger("zentral.utils.os_version")


def make_comparable_os_version(os_version):
    try:
        return tuple(
            i or j for i, j in zip_longest(
              (int(i) for i in os_version.split(".")),
              (0, 0, 0)
            )
        )
    except Exception:
        logger.warning("Cannot parse OS version %s", os_version)
        return (0, 0, 0)
