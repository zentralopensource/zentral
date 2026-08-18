import os
import re

from django.apps import apps
from django.conf import settings
from django.test import SimpleTestCase

from pbac.engine import engine


# perms.<app_label>.<codename>, or perms.<app_label> for a module wide check
PERMS_RE = re.compile(r"\bperms\.(?P<app_label>\w+)(?:\.(?P<codename>\w+))?")

# BASE_DIR is the server/ directory, the templates are spread over the whole repository
REPO_DIR = os.path.dirname(settings.BASE_DIR)


class TemplatePermissionsTestCase(SimpleTestCase):
    maxDiff = None

    def iter_template_paths(self):
        roots = list(settings.TEMPLATES[0]["DIRS"])
        roots.extend(app_config.path for app_config in apps.get_app_configs())
        for root in roots:
            for dirpath, _, filenames in os.walk(root):
                for filename in filenames:
                    if filename.endswith(".html"):
                        yield os.path.join(dirpath, filename)

    def test_template_permissions_are_registered(self):
        checked = 0
        unknown = []
        for path in sorted(set(self.iter_template_paths())):
            with open(path) as f:
                for line_number, line in enumerate(f, 1):
                    for match in PERMS_RE.finditer(line):
                        app_label, codename = match.group("app_label"), match.group("codename")
                        checked += 1
                        if codename:
                            if f"{app_label}.{codename}" in engine.legacy_perm_actions:
                                continue
                        elif app_label in engine.module_legacy_perm_actions:
                            continue
                        unknown.append(f"{os.path.relpath(path, REPO_DIR)}:{line_number} {match.group()}")
        self.assertEqual(unknown, [])
        # a scan that finds nothing would pass without checking anything
        self.assertGreater(checked, 100)
