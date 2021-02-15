import os
from django.utils.functional import SimpleLazyObject


def _get_flags_filepath(filename):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)


def _iter_flags(filepath):
    with open(filepath, "r") as f:
        for line in f:
            if not line.startswith("--"):
                continue
            flag, rest = line[2:].split(" ", 1)
            yield flag, rest.startswith("VALUE") or rest.startswith("PATH")


def get_cli_only_flags():
    return dict(_iter_flags(_get_flags_filepath("cli_only_flags.txt")))


cli_only_flags = SimpleLazyObject(get_cli_only_flags)


def get_cli_only_flags_blocklist():
    return dict(_iter_flags(_get_flags_filepath("cli_only_flags_blocklist.txt")))


cli_only_flags_blocklist = SimpleLazyObject(get_cli_only_flags_blocklist)
