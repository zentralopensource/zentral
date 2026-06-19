import re
from django.utils.text import Truncator


MAX_WORKSHEET_NAME_LENGTH = 31

# xlsxwriter rejects worksheet names that are > 31 chars, contain any of []:*?/\,
# start/end with "'", or collide case-insensitively. See Workbook._check_sheetname:
# https://github.com/jmcnamara/XlsxWriter/blob/f5f7ecdb62c1b26bfb5d92f438557c54a635188c/xlsxwriter/workbook.py#L826-L870
_INVALID_WORKSHEET_NAME_CHARS = re.compile(r"[\[\]:*?/\\]")


def _safe_worksheet_name(name, used_names=None):
    name = _INVALID_WORKSHEET_NAME_CHARS.sub(" ", str(name))
    name = re.sub(r"\s+", " ", name).strip(" '")
    name = Truncator(name).chars(MAX_WORKSHEET_NAME_LENGTH).strip(" '") or "Sheet"
    if used_names is None:
        return name
    lower_used = {u.lower() for u in used_names}
    candidate = name
    suffix_n = 1
    while candidate.lower() in lower_used:
        suffix_n += 1
        suffix = f" ({suffix_n})"
        base = Truncator(name).chars(MAX_WORKSHEET_NAME_LENGTH - len(suffix)).strip(" '") or "Sheet"
        candidate = f"{base}{suffix}"
    used_names.add(candidate)
    return candidate


def add_worksheet(workbook, name):
    # The workbook itself is the source of truth for already-used names, so
    # callers never have to thread a set through their sheet loops.
    used_names = {ws.name for ws in workbook.worksheets()}
    return workbook.add_worksheet(_safe_worksheet_name(name, used_names))
