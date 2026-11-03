from pathlib import Path
import re

from django.test import SimpleTestCase

from pbac.engine import DEPRECATED_HELP_TEXT, engine


REPOSITORY = Path(__file__).resolve().parents[2]
DEPRECATED_WRITE_MODELS = {
    "accounts": ("apitoken", "oidcapitokenissuer", "user"),
    "auth": ("group",),
    "realms": ("realm", "realmgroup", "realmgroupmapping", "realmuser", "rolemapping"),
}


def deprecated_perms():
    return sorted(
        f"{app_label}.{operation}_{model}"
        for app_label, models in DEPRECATED_WRITE_MODELS.items()
        for model in models
        for operation in ("add", "change", "delete")
    )


class DeprecatedActionsTestCase(SimpleTestCase):
    """Until the delegated administration, a superuser makes the writes of the identity objects.

    Their legacy actions are deprecated: they stay in the schema, so that the stored policies that name
    them still save, they give nothing, and a later version removes them. They give nothing as long as no
    code checks them: a has_perm() call or a perms.… in a template would make each policy that names them
    grant again. The identity API endpoints have no write handler, see their method-not-allowed tests.
    """

    def test_deprecated_actions_help_text(self):
        self.assertEqual(
            sorted(perm for perm, action in engine.legacy_perm_actions.items()
                   if action.help_text == DEPRECATED_HELP_TEXT),
            deprecated_perms(),
        )

    def test_no_code_checks_a_deprecated_action(self):
        pattern = re.compile(r"\b(?:" + "|".join(re.escape(p) for p in deprecated_perms()) + r")\b")
        checked = 0
        found = []
        for top in ("server", "zentral", "ee"):
            for path in sorted((REPOSITORY / top).rglob("*")):
                if path.suffix not in (".py", ".html") or "migrations" in path.parts:
                    continue
                checked += 1
                for lineno, line in enumerate(path.read_text().splitlines(), 1):
                    if pattern.search(line):
                        found.append(f"{path.relative_to(REPOSITORY)}:{lineno}")
        # a walk that read no file would assert nothing
        self.assertGreater(checked, 500)
        self.assertEqual(found, [])
