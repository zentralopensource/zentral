from datetime import datetime, timezone

from dateutil import parser
from django.utils.timezone import is_aware, make_naive


def duration_repr(seconds):
    result = []
    for divisor, unit in ((3600 * 24, "d"), (3600, "h"), (60, "m"), (1, "s")):
        n, seconds = divmod(seconds, divisor)
        if n:
            result.append(f"{n}{unit}")
    return " ".join(result)


def naive_truncated_isoformat(t, timespec="seconds"):
    return t.isoformat(timespec=timespec).split("+")[0]


def naive_utc_fromisoformat(s):
    dt = datetime.fromisoformat(s)
    if is_aware(dt):
        dt = make_naive(dt)
    return dt


def parse_naive_datetime(value):
    dt = parser.parse(value)
    if is_aware(dt):
        dt = make_naive(dt)
    return dt


def naive_utcnow():
    """Naive UTC datetime, replacing the deprecated datetime.utcnow().

    Returns the current UTC datetime stripped of its tzinfo so the value
    keeps comparing and serializing the same way as datetime.utcnow() did.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def naive_utcfromtimestamp(ts):
    """Naive UTC datetime from a POSIX timestamp, replacing the deprecated
    datetime.utcfromtimestamp().
    """
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
