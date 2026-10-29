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
        supplemental_os_version_extra = supplemental_os_version_extra.strip()
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


def comparable_os_version_in_range(comparable_os_version,
                                   min_comparable_os_version=None, max_comparable_os_version=None):
    if min_comparable_os_version and comparable_os_version < tuple(min_comparable_os_version):
        return False
    if max_comparable_os_version and comparable_os_version >= tuple(max_comparable_os_version):
        return False
    return True


def os_version_in_range(os_version, min_os_version="", max_os_version=""):
    """Half-open range on the raw versions. A version that is missing or does not parse never matches a bound."""
    if not min_os_version and not max_os_version:
        return True
    comparable_os_version = make_comparable_os_version(os_version) if os_version else (0, 0, 0)
    if comparable_os_version == (0, 0, 0):
        return False
    return comparable_os_version_in_range(
        comparable_os_version,
        make_comparable_os_version(min_os_version) if min_os_version else None,
        make_comparable_os_version(max_os_version) if max_os_version else None,
    )


def validate_os_version_bound(os_version):
    """Raise a ValueError if os_version cannot be a bound of a range.

    A supplemental extra and a fourth component are refused: the bounds must compare with each other and with
    a device version, and an extra is a string where a fourth component is an integer.
    """
    if not os_version:
        return
    if len(os_version.split()) > 1:
        raise ValueError("A supplemental OS version extra is not supported")
    if len(os_version.split(".")) > 3:
        raise ValueError("An OS version has at most three components")
    if make_comparable_os_version(os_version) == (0, 0, 0):
        raise ValueError("Not a valid OS version")


def validate_os_version_range(min_os_version, max_os_version):
    """Raise a ValueError if the two bounds do not make a range. Call it on validated bounds only."""
    if (
        min_os_version and max_os_version
        and make_comparable_os_version(min_os_version) >= make_comparable_os_version(max_os_version)
    ):
        raise ValueError("Must be greater than the minimum OS version")
