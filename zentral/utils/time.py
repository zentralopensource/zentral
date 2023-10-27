def duration_repr(seconds):
    result = []
    for divisor, unit in ((3600 * 24, "d"), (3600, "h"), (60, "m"), (1, "s")):
        n, seconds = divmod(seconds, divisor)
        if n:
            result.append(f"{n}{unit}")
    return " ".join(result)


def naive_truncated_isoformat(t, timespec="seconds"):
    return t.isoformat(timespec=timespec).split("+")[0]
