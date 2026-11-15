import ast
import re
from pathlib import Path

from django.test import SimpleTestCase


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIRS = ("ee", "server", "zentral")

# The helpers of zentral/contrib/inventory/utils/tags.py trust their caller: they make no decision. So each
# caller is in one of the lists below, with the decision that covers it. A new caller fails these tests until
# someone decides how it is authorized, and adds it here.

TAG_HELPERS = {
    "add_machine_tags",
    "remove_machine_tags",
    "set_machine_taxonomy_tags",
    "set_machine_taxonomy_tags_and_yield_events",
}

SAVE = "tagAnyMachine on each tag of the object, when the object is saved"

TAG_HELPER_CALLERS = {
    # decided in the request
    "zentral/contrib/inventory/api_views.py": "tagAnyMachine on each tag, in the request",
    "zentral/contrib/inventory/views.py": "createMachineTag and deleteMachineTag on the machine, in the request",
    # the enrollment secret tags, when a device enrolls
    "zentral/contrib/mdm/public_views/mdm.py": SAVE,
    "zentral/contrib/monolith/public_views.py": SAVE,
    "zentral/contrib/munki/public_views.py": SAVE,
    "zentral/contrib/osquery/public_views.py": SAVE,
    "zentral/contrib/santa/public_views.py": SAVE,
    "zentral/contrib/turbo/public_views/enrollment.py": SAVE,
    # the realm group tag mappings, when a realm user is linked to a device
    "zentral/contrib/mdm/inventory.py": SAVE,
    # the tag of a query, when a result comes in
    "zentral/contrib/osquery/tags.py": SAVE,
    # the tag of a script, when a result comes in
    "zentral/contrib/turbo/results.py": SAVE,
    # the tag configuration of a Jamf instance, when a webhook event comes in
    "zentral/contrib/jamf/preprocessors/webhook.py": "createTag on the taxonomy and tagAnyMachine on each of "
                                                     "its tags, when the tag configuration is saved",
}

# The writes of the machine tags that do not use the helpers.

MACHINE_TAG_WRITE_RES = (
    re.compile(r"(insert\s+into|delete\s+from|update)\s+inventory_machinetag", re.IGNORECASE),
    re.compile(r"\bMachineTag\.objects\.(create|bulk_create|get_or_create|update_or_create)\("),
    re.compile(r"(?<!class )\bMachineTag\("),
)

MACHINE_TAG_WRITERS = {
    "zentral/contrib/inventory/utils/tags.py": "the helpers",
    # the realm group tag mappings of a realm, when a mapping is saved or deleted, or when the groups change
    "zentral/contrib/mdm/inventory.py": SAVE,
    # the group tag mappings of a connection, in the tag sync
    "zentral/contrib/google_workspace/utils.py": SAVE,
}

# The creations of tags.

TAG_CREATION_RES = (
    re.compile(r"insert\s+into\s+inventory_tag\b", re.IGNORECASE),
    re.compile(r"(?<![A-Za-z_])Tag\.objects\.(create|bulk_create|get_or_create|update_or_create)\("),
    re.compile(r"(?<!class )(?<![A-Za-z_])Tag\("),
)

TAG_CREATORS = {
    # the tag API and the tag form use the model serializer and the model form: createTag, in the request
    "zentral/contrib/inventory/utils/tags.py": "createTag on the taxonomy, when the Jamf tag configuration is saved",
}


def iter_sources():
    for source_dir in SOURCE_DIRS:
        for path in sorted((REPOSITORY_ROOT / source_dir).rglob("*.py")):
            if "migrations" in path.parts:
                continue
            yield path.relative_to(REPOSITORY_ROOT).as_posix(), path.read_text()


def matching_paths(regexes):
    return {path for path, source in iter_sources() if any(regex.search(source) for regex in regexes)}


def called_names(source):
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                yield func.id
            elif isinstance(func, ast.Attribute):
                # not a method of the same name
                if not (isinstance(func.value, ast.Name) and func.value.id == "self"):
                    yield func.attr


class TaggingCallersTestCase(SimpleTestCase):
    maxDiff = None

    def test_tag_helper_callers(self):
        callers = set()
        for path, source in iter_sources():
            if path == "zentral/contrib/inventory/utils/tags.py":
                continue
            if not any(name in source for name in TAG_HELPERS):
                continue
            if TAG_HELPERS.intersection(called_names(source)):
                callers.add(path)
        self.assertEqual(callers, set(TAG_HELPER_CALLERS))

    def test_tag_helpers_exist(self):
        from zentral.contrib.inventory.utils import tags
        self.assertEqual(
            {name for name in tags.__all__ if not name.startswith("send_")},
            TAG_HELPERS,
        )

    def test_machine_tag_writers(self):
        self.assertEqual(matching_paths(MACHINE_TAG_WRITE_RES), set(MACHINE_TAG_WRITERS))

    def test_tag_creators(self):
        self.assertEqual(matching_paths(TAG_CREATION_RES), set(TAG_CREATORS))
