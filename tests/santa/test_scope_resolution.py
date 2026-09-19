from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import Tag
from zentral.contrib.santa.models import Configuration, MachineRule, ScopedClientMode
from .utils import force_configuration, force_enrolled_machine, force_rule


SERIAL, USER, TAG, ALL = (ScopedClientMode.RANK_SERIAL, ScopedClientMode.RANK_USER,
                          ScopedClientMode.RANK_TAG, ScopedClientMode.RANK_ALL)

# The scope table of the design: one statement, one machine, the level that decided.
# None: the statement is out for the machine. The tags are names, the test case resolves them.
SCOPE_CASES = (
    ("matched by its serial number",
     {"serial_numbers": ["S1"], "tags": ["vip"]},
     {"serial_number": "S1"}, SERIAL),
    ("matched by its serial number and its tag, the serial number decides",
     {"serial_numbers": ["S1"], "tags": ["vip"]},
     {"serial_number": "S1", "tags": ["vip"]}, SERIAL),
    ("matched by a tag only",
     {"serial_numbers": ["S1"], "tags": ["vip"]},
     {"serial_number": "S2", "tags": ["vip"]}, TAG),
    ("not matched, and the statement has scope fields",
     {"serial_numbers": ["S1"], "tags": ["vip"]},
     {"serial_number": "S3"}, None),
    ("excluded by its serial number, matched by a tag",
     {"tags": ["fleet"], "excluded_serial_numbers": ["S1"]},
     {"serial_number": "S1", "tags": ["fleet"]}, None),
    ("matched by its serial number, a wider exclusion is not looked at",
     {"serial_numbers": ["S1"], "excluded_tags": ["contractors"]},
     {"serial_number": "S1", "tags": ["contractors"]}, SERIAL),
    ("a tag of each field, the exclusion wins",
     {"tags": ["vip"], "excluded_tags": ["contractors"]},
     {"serial_number": "S6", "tags": ["vip", "contractors"]}, None),
    ("no scope field, everyone",
     {"excluded_tags": ["contractors"]},
     {"serial_number": "S4", "tags": ["vip"]}, ALL),
    ("no scope field, excluded by a tag",
     {"excluded_tags": ["contractors"]},
     {"serial_number": "S4", "tags": ["contractors"]}, None),
    ("no primary user, not matched by the primary users",
     {"primary_users": ["alice"]},
     {"serial_number": "S5"}, None),
    ("no primary user, not excluded by the excluded primary users",
     {"tags": ["fleet"], "excluded_primary_users": ["bob"]},
     {"serial_number": "S5", "tags": ["fleet"]}, TAG),
    ("matched by its primary user",
     {"primary_users": ["alice"]},
     {"serial_number": "S7", "primary_user": "alice"}, USER),
    ("matched by its primary user and its tag, the primary user decides",
     {"primary_users": ["alice"], "tags": ["fleet"]},
     {"serial_number": "S7", "primary_user": "alice", "tags": ["fleet"]}, USER),
    ("excluded by its primary user, matched by a tag",
     {"tags": ["fleet"], "excluded_primary_users": ["alice"]},
     {"serial_number": "S7", "primary_user": "alice", "tags": ["fleet"]}, None),
    ("matched by its primary user, a wider exclusion is not looked at",
     {"primary_users": ["alice"], "excluded_tags": ["contractors"]},
     {"serial_number": "S7", "primary_user": "alice", "tags": ["contractors"]}, USER),
    ("excluded by its serial number, matched by its primary user",
     {"primary_users": ["alice"], "excluded_serial_numbers": ["S7"]},
     {"serial_number": "S7", "primary_user": "alice"}, None),
    ("no scope field, no exclusion",
     {},
     {"serial_number": "S8"}, ALL),
    ("no scope field, excluded by its primary user",
     {"excluded_primary_users": ["alice"]},
     {"serial_number": "S8", "primary_user": "alice"}, None),
)


class SantaScopeResolutionTestCase(TestCase):
    """The scope table, run against the rule download and against the scoped items.

    The semantics are implemented twice, as SQL for the rules and as an ORM annotation for the
    entries. One table keeps them together.
    """

    @classmethod
    def setUpTestData(cls):
        cls.configuration = force_configuration()
        cls.tags = {name: Tag.objects.create(name=f"{name}-{get_random_string(8)}")
                    for name in ("vip", "fleet", "contractors")}

    def tag_ids(self, machine):
        return [self.tags[name].pk for name in machine.get("tags", [])]

    def split_statement(self, statement):
        fields = {k: v for k, v in statement.items() if not k.endswith("tags")}
        tags = {k: [self.tags[n] for n in v] for k, v in statement.items() if k.endswith("tags")}
        return fields, tags

    def test_rules(self):
        for description, statement, machine, expected_rank in SCOPE_CASES:
            with self.subTest(description):
                fields, tags = self.split_statement(statement)
                rule = force_rule(configuration=self.configuration, **fields)
                for field, field_tags in tags.items():
                    getattr(rule, field).set(field_tags)
                enrolled_machine = force_enrolled_machine(configuration=self.configuration,
                                                          serial_number=machine["serial_number"],
                                                          primary_user=machine.get("primary_user"))
                new_rules = MachineRule.objects._iter_new_rules(enrolled_machine, self.tag_ids(machine))
                ranks = [r["match_rank"] for r in new_rules if r["target_id"] == rule.target_id]
                self.assertEqual(ranks, [] if expected_rank is None else [expected_rank])

    def test_entries(self):
        for description, statement, machine, expected_rank in SCOPE_CASES:
            with self.subTest(description):
                fields, tags = self.split_statement(statement)
                configuration = force_configuration()
                entry = ScopedClientMode.objects.create(configuration=configuration,
                                                        name=get_random_string(12),
                                                        client_mode=Configuration.LOCKDOWN_MODE,
                                                        **fields)
                for field, field_tags in tags.items():
                    getattr(entry, field).set(field_tags)
                entries = ScopedClientMode.objects.for_machine(configuration,
                                                               machine["serial_number"],
                                                               machine.get("primary_user"),
                                                               self.tag_ids(machine))
                ranks = [e.match_rank for e in entries if e.pk == entry.pk]
                self.assertEqual(ranks, [] if expected_rank is None else [expected_rank])
