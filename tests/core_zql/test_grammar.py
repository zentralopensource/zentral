import os
from django.test import SimpleTestCase
from lark import Lark, Token, Tree
from lark.exceptions import LarkError


GRAMMAR_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "zentral", "core", "zql", "grammar.lark")


def load_grammar(**kwargs):
    with open(GRAMMAR_PATH, "r", encoding="utf-8") as f:
        return Lark(f.read(), **kwargs)


# the query examples of the ZQL design, a where clause or a stage alone completed by a source
ACCEPTED_QUERIES = (
    # the language
    'events\n'
    '| where created_at > now() - 7d and type == "santa_event"\n'
    '| where payload.decision == "BLOCK_UNKNOWN"\n'
    '| stats count() as n by serial_number\n'
    '| sort n desc\n'
    '| limit 20',
    'events | where type == "mdm_request" and created_at > now() - 7d\n'
    '       | stats count() as requests,\n'
    '               countIf(payload.status == "failure") as failures,\n'
    '               countDistinctIf(serial_number, payload.status == "failure") as failing_devices\n'
    '         by dateTrunc(created_at, 1d) as day',
    'events | where machine.tags[0].name == "build"',
    'events | where machine.tags[].name == "build"',
    'events | where machine.tags.0 == "build"',
    'events | where machine.tags.`odd key` == "build"',
    'events | where machine.tags[].name has any ("build", "ci")',
    'events | where machine.tags[].name has any ("x") and machine.tags[].id has any (5)',
    '// audit events about objects changed in the last week, by the object\'s own clock\n'
    'events | where type == "zentral_audit" and toDateTime(payload.object.new_value.updated_at) > now() - 7d',
    '// santa executions per day, read from the agent\'s epoch float\n'
    'events | where type == "santa_event"\n'
    '       | stats count() by dateTrunc(toDateTime(payload.execution_time), 1d) as day',
    'events | where created_at > now() - 30d and created_at < created_at + 1h',
    'events | where toDateTime(payload.execution_time) + 1d > now()',
    'events | where created_at > "2026-12-01"',
    'events | where type == "santa_event" | limit 1 | fields payload',
    'events | where serial_number == "C02EXAMPLE01" | fields created_at, type, payload',
    'events | where type == "santa_event" | sort created_at desc',
    'events | where type == "santa_event" | stats count() as n by machine.platform | sort machine.platform, n desc',
    'events | where type == "santa_event" | sort toNumber(payload.duration) desc',
    '// how the fleet spreads across this week\'s block counts\n'
    'events | where type == "santa_event" and payload.decision == "BLOCK_UNKNOWN"\n'
    '              and created_at > now() - 7d\n'
    '       | stats count() as blocks by serial_number\n'
    '       | stats count() as machines by blocks\n'
    '       | sort blocks',
    '// how many devices started failing each day — the onset curve of an incident\n'
    'events | where type == "mdm_request" and payload.status == "failure"\n'
    '       | stats min(created_at) as first_failure by serial_number\n'
    '       | stats count() as devices by dateTrunc(first_failure, 1d) as day',
    'events | where type == "santa_event" and created_at > now() - 1d | paths',
    'events | where created_at > now() - 1d | paths by type       // which envelope paths each type carries',
    'events | where created_at > now() - 1d | paths | where path startswith "payload."',
    # the queries v1 has to serve
    '// the machine events page\n'
    'events | where serial_number == "C02EXAMPLE01" | sort created_at desc | limit 50',
    '// the santa configuration events page\n'
    'events | where linked(Santa::Configuration, 18) | sort created_at desc | limit 50',
    '// what is failing, and how much\n'
    'events | where type == "mdm_request" and payload.status == "failure"\n'
    '       | stats count() as n, countDistinct(serial_number) as devices by payload.reason\n'
    '       | sort n desc',
    '// agent version rollout\n'
    'events | where type == "santa_preflight" and created_at > now() - 7d\n'
    '       | stats countDistinct(serial_number) as machines by request.user_agent',
    '// what an undocumented type carries\n'
    'events | where type == "munki_request" and created_at > now() - 1d | paths',
    '// an incident\'s daily summary, in one query\n'
    'events | where type == "mdm_request" and created_at > now() - 7d\n'
    '       | stats count() as requests, countIf(payload.status == "failure") as failures\n'
    '         by dateTrunc(created_at, 1d) as day',
    'events | stats count() as n, countDistinct(serial_number) as machines, min(created_at) as first by type',
    # the endpoint
    'events | stats count() as n, countDistinct(serial_number) as devices by type',
    'events | stats count()',
    'events | stats count() by type',
    'events | where type == "santa_event"\n'
    '       | stats count() by dateTrunc(created_at, 1d) as day, serial_number',
    'events | where type == "santa_event" | sort created_at desc | limit 100',
    'events | where type == "santa_event" and created_at < "2026-08-29T09:14:02.117Z"\n'
    '       | sort created_at desc | limit 100',
    'events | where id > 4820',
    # fields
    'events | where request.user_agent contains "santactl"      // not metadata.request.user_agent',
    'events | where machine.platform == "MACOS"                 // not metadata.machine.platform',
    'events | where payload.decision == "BLOCK_UNKNOWN"         // payload keeps its prefix',
    'events | where machine.osquery.name == "a" or machine.munki.os_version == "b" or machine.santa.name == "c"'
    ' or machine.mdm.name == "d" or machine.`workspace-one`.name == "e" or machine.`google-workspace`.name == "f"',
    'events | where coalesce(machine.osquery.name, machine.munki.name) == "build-07"',
    'events | where isPresent(payload.decision) and isNumeric(payload.duration) and toString(payload.pid) == "1"',
    'events | where payload.decision is null or payload.decision is not null',
    # linked objects, and probe matches
    'events | where linked(Santa::Configuration, 18)              // ownership — an entity type and its key',
    'events | where linked(Mdm::Asset, "1234567", "STDQ")         // ownership — a two-part invariant key',
    'events | where linked("file", "sha256", "3f2a…")             // mention — an object key and its args',
    'events | where linked("aple_team_id", "ABCD")',
    'events | where linked(Inventory::Machine, "C02EXAMPLE01")',
    'events | where linked(Monolith::PkgInfoName, 42)          // this row, however it is named\n'
    '   or linked("munki_pkginfo_name", "Firefox")    // this name, as any agent reported it',
    'events | where probe(12)                           // events probe 12 matched',
    'events | where linked(Probes::ProbeSource, 12)     // audit events about probe 12',
    # authorization
    'events | where payload.executing_user == "alice" and payload.decision == "BLOCK_UNKNOWN"\n'
    '       | stats count() by dateTrunc(created_at, 1d) as day',
    'events | stats count() by payload.executing_user',
    'events | where (linked(Inventory::MetaBusinessUnit, 3) or linked(Santa::Configuration, 18))\n'
    '        and not linked(Inventory::MetaBusinessUnit, 4)',
    'events | where linked(Inventory::MetaBusinessUnit, 3) or linked(Inventory::MetaBusinessUnit, 4)',
    'events | where machine.tags[].id has any (3) and machine.platform in ("MACOS", "IOS")',
    'events | stats count() | where count > 10',
    # the lexical rules
    'events | where payload.text == "a \\"quoted\\" word, and a \\\\ backslash"',
    'events | where payload.text == "\\/ \\b \\f \\n \\r \\t \\u00e9 \\u00E9"',
    'events | where payload.text == "é…"',
    'events | where payload.count >= -1 and payload.ratio < 0.5 and payload.delta != -2.25',
    'events | where payload.enabled == true and payload.disabled == false',
    'events | where payload.`true` == true and payload.not == 1 and `true` == 2 and payload.linked == 3'
    ' and payload.null == 4 and `null` == 5',
    'events | where created_at > now() - 30s and created_at > now() - 5m and created_at > now() - 2w',
    'events | where payload.list has all ("a", "b")',
    'events | where payload.path endswith ".app" and payload.path startswith "/Applications/"',
    'events | sort created_at asc, type',
    'events | fields `odd key`',
    'events | where x == 1 // a comment\n// another comment\n| limit 1',
)


REJECTED_QUERIES = (
    # a backtick segment cannot contain a dot, which is always a separator
    'events | where payload.`os.release.full` == "22.04"',
    'events | where `os.release`.full == "22.04"',
    # = for ==
    'events | where type = "santa_event"',
    # comparisons do not chain
    'events | where a < b < c',
    'events | where a == b == c',
    # no null literal
    'events | where payload.decision == null',
    'events | where null == payload.decision',
    # the only arithmetic is a datetime plus or minus a duration
    'events | where payload.count + 1 > 2',
    'events | where created_at > now() - 7d - created_at',
    # durations: an integer and one of s m h d w
    'events | where created_at > now() - 1mo',
    'events | where created_at > now() - 1.5d',
    'events | where created_at > now() - 7days',
    'events | where created_at > now() - 7 d',
    # numbers: no exponent, no leading dot
    'events | where payload.count > 1e3',
    'events | where payload.ratio > .5',
    # strings: double quotes, the JSON escapes only, no control character
    "events | where type == 'santa_event'",
    'events | where type == "santa_event',
    'events | where payload.text == "a\\xb"',
    'events | where payload.text == "\\u00e"',
    'events | where payload.text == "\\U00e9"',
    'events | where payload.text == "a\nb"',
    'events | where payload.text == "a\tb"',
    # lists: one or more, no trailing comma
    'events | where type in ()',
    'events | where type in ("a", "b",)',
    'events | where type in "a"',
    'events | where machine.tags[].name has ("build")',
    'events | where type not in ("a")',
    # paths
    'events | where machine.tags[-1].name == "x"',
    'events | where machine.tags[name == "x" and id == 5]',
    'events | where machine..tags == "x"',
    'events | where machine.tags. == "x"',
    'events | where `` == "x"',
    # the entity type is in linked() only
    'events | where linked(santa_configuration, 18)',
    'events | where linked(Santa::Configuration)',
    'events | where linked(Santa::Configuration, payload.id)',
    'events | where type == Santa::Configuration',
    'events | where linked == 1',
    'events | where not == 1',
    # verbs, operators and functions are case-sensitive keywords
    'events | Where type == "santa_event"',
    'events | where a == 1 AND b == 2',
    # incomplete queries
    '',
    '| where type == "santa_event"',
    'events |',
    'events | where',
    'events | where type == "santa_event" and',
    'events | where (type == "santa_event"',
    'events | where payload.decision is',
    'events | where not',
    'events | stats',
    'events | stats count() by',
    'events | stats count() as',
    'events | stats count() as true',
    'events | stats count() as `n`',
    'events | sort',
    'events | sort created_at descending',
    'events | limit',
    'events | limit -1',
    'events | limit 1.5',
    'events | limit n',
    'events | fields',
    'events | paths by',
    # an aggregation is a function call
    'events | stats n',
    # fields keeps top-level keys
    'events | fields payload.decision',
    # stages are separated by |
    'events where type == "santa_event"',
    'events | where type == "santa_event" limit 1',
)


def to_sexp(node):
    if isinstance(node, Token):
        return str(node)
    if isinstance(node, Tree):
        return (node.data, *(to_sexp(child) for child in node.children))
    return node


class ZQLGrammarTestCase(SimpleTestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.parser = load_grammar(parser="lalr")

    def parse_where(self, expr):
        tree = self.parser.parse(f"events | where {expr}")
        query = tree.children[0]
        self.assertEqual(len(query.children), 2)
        where = query.children[1]
        self.assertEqual(where.data, "where")
        return to_sexp(where.children[0])

    # accept

    def test_accepted_queries(self):
        for query in ACCEPTED_QUERIES:
            with self.subTest(query=query):
                self.assertEqual(self.parser.parse(query).data, "start")

    # reject

    def test_rejected_queries(self):
        for query in REJECTED_QUERIES:
            with self.subTest(query=query):
                with self.assertRaises(LarkError):
                    self.parser.parse(query)

    # shape

    def test_and_binds_tighter_than_or(self):
        self.assertEqual(
            self.parse_where("a or b and c"),
            ("or_", ("path", "a"), ("and_", ("path", "b"), ("path", "c")))
        )
        self.assertEqual(
            self.parse_where("a and b or c"),
            ("or_", ("and_", ("path", "a"), ("path", "b")), ("path", "c"))
        )

    def test_parentheses_group(self):
        self.assertEqual(
            self.parse_where("(a or b) and c"),
            ("and_", ("or_", ("path", "a"), ("path", "b")), ("path", "c"))
        )

    def test_and_or_left_associative(self):
        self.assertEqual(
            self.parse_where("a and b and c"),
            ("and_", ("and_", ("path", "a"), ("path", "b")), ("path", "c"))
        )
        self.assertEqual(
            self.parse_where("a or b or c"),
            ("or_", ("or_", ("path", "a"), ("path", "b")), ("path", "c"))
        )

    def test_not_binds_looser_than_comparison(self):
        self.assertEqual(
            self.parse_where('not a == "x"'),
            ("not_", ("compare", ("path", "a"), "==", '"x"'))
        )

    def test_not_binds_tighter_than_and(self):
        self.assertEqual(
            self.parse_where("not a and b"),
            ("and_", ("not_", ("path", "a")), ("path", "b"))
        )
        self.assertEqual(
            self.parse_where("not not a"),
            ("not_", ("not_", ("path", "a")))
        )

    def test_membership_binds_tighter_than_comparison(self):
        self.assertEqual(
            self.parse_where('a in ("x") == true'),
            ("compare", ("in_", ("path", "a"), ("list", '"x"')), "==", ("boolean", "true"))
        )
        self.assertEqual(
            self.parse_where('a == b is null'),
            ("compare", ("path", "a"), "==", ("is_null", ("path", "b")))
        )

    def test_membership_operators(self):
        for operator, data in (("contains", "contains"),
                               ("startswith", "startswith"),
                               ("endswith", "endswith")):
            with self.subTest(operator=operator):
                self.assertEqual(
                    self.parse_where(f'a {operator} "x"'),
                    (data, ("path", "a"), '"x"')
                )
        self.assertEqual(
            self.parse_where('a has any ("x", 1)'),
            ("has_any", ("path", "a"), ("list", '"x"', "1"))
        )
        self.assertEqual(
            self.parse_where('a has all (true, 1d)'),
            ("has_all", ("path", "a"), ("list", ("boolean", "true"), "1d"))
        )
        self.assertEqual(
            self.parse_where('a is not null'),
            ("is_not_null", ("path", "a"))
        )

    def test_datetime_arithmetic_binds_tighter_than_comparison(self):
        self.assertEqual(
            self.parse_where("created_at > now() - 7d"),
            ("compare",
             ("path", "created_at"),
             ">",
             ("datetime_arithmetic", ("call", "now"), "-", "7d"))
        )

    def test_datetime_arithmetic_left_associative(self):
        self.assertEqual(
            self.parse_where("now() - 7d + 1h == created_at"),
            ("compare",
             ("datetime_arithmetic", ("datetime_arithmetic", ("call", "now"), "-", "7d"), "+", "1h"),
             "==",
             ("path", "created_at"))
        )

    def test_datetime_arithmetic_binds_tighter_than_membership(self):
        self.assertEqual(
            self.parse_where('a contains created_at + 1h'),
            ("contains", ("path", "a"), ("datetime_arithmetic", ("path", "created_at"), "+", "1h"))
        )

    def test_negative_number_is_a_literal(self):
        self.assertEqual(
            self.parse_where("a > -1.5"),
            ("compare", ("path", "a"), ">", "-1.5")
        )

    def test_path_against_index(self):
        self.assertEqual(
            self.parse_where("machine.tags[0].name"),
            ("path", "machine", ("member", "tags"), ("index", "0"), ("member", "name"))
        )
        self.assertEqual(
            self.parse_where("machine.tags[].name"),
            ("path", "machine", ("member", "tags"), ("flatten",), ("member", "name"))
        )
        self.assertEqual(
            self.parse_where("machine.tags.0"),
            ("path", "machine", ("member", "tags"), ("member", "0"))
        )
        self.assertEqual(
            self.parse_where("machine.`odd key`.name"),
            ("path", "machine", ("member", "`odd key`"), ("member", "name"))
        )

    def test_keywords_at_the_head_of_an_expression(self):
        self.assertEqual(
            self.parse_where("true == `true`"),
            ("compare", ("boolean", "true"), "==", ("path", "`true`"))
        )
        self.assertEqual(
            self.parse_where("payload.true == payload.not"),
            ("compare",
             ("path", "payload", ("member", "true")),
             "==",
             ("path", "payload", ("member", "not")))
        )

    def test_linked(self):
        self.assertEqual(
            self.parse_where('linked(Mdm::Asset, "1234567", "STDQ")'),
            ("linked", "Mdm::Asset", '"1234567"', '"STDQ"')
        )
        self.assertEqual(
            self.parse_where('linked("file", "sha256", "3f2a")'),
            ("linked", '"file"', '"sha256"', '"3f2a"')
        )

    def test_stages(self):
        tree = self.parser.parse(
            "events"
            " | where a == 1"
            " | stats count() as n, countIf(b == 2) by dateTrunc(created_at, 1d) as day, c"
            " | stats max(n) as m"
            " | sort m desc, day"
            " | limit 10"
        )
        self.assertEqual(
            to_sexp(tree),
            ("start",
             ("query",
              ("source", "events"),
              ("where", ("compare", ("path", "a"), "==", "1")),
              ("stats",
               ("aggregation", ("call", "count"), ("alias", "n")),
               ("aggregation", ("call", "countIf", ("compare", ("path", "b"), "==", "2"))),
               ("group_by",
                ("group_key", ("call", "dateTrunc", ("path", "created_at"), "1d"), ("alias", "day")),
                ("group_key", ("path", "c")))),
              ("stats", ("aggregation", ("call", "max", ("path", "n")), ("alias", "m"))),
              ("sort",
               ("sort_key", ("path", "m"), ("sort_order", "desc")),
               ("sort_key", ("path", "day"))),
              ("limit", "10")))
        )

    def test_fields_and_paths(self):
        self.assertEqual(
            to_sexp(self.parser.parse("events | fields created_at, `odd key` | paths by type as t")),
            ("start",
             ("query",
              ("source", "events"),
              ("fields", "created_at", "`odd key`"),
              ("paths", ("group_by", ("group_key", ("path", "type"), ("alias", "t"))))))
        )

    # the contextual lexer emits a keyword only where the grammar accepts one

    def test_keyword_as_group_key(self):
        self.assertEqual(
            to_sexp(self.parser.parse("events | stats count() by by")),
            ("start",
             ("query",
              ("source", "events"),
              ("stats", ("aggregation", ("call", "count")), ("group_by", ("group_key", ("path", "by"))))))
        )

    def test_keyword_as_field(self):
        self.assertEqual(
            self.parse_where('by == "x"'),
            ("compare", ("path", "by"), "==", '"x"')
        )
        self.assertEqual(
            self.parse_where('where == "x" and stats.limit == 1'),
            ("and_",
             ("compare", ("path", "where"), "==", '"x"'),
             ("compare", ("path", "stats", ("member", "limit")), "==", "1"))
        )

    # ambiguity

    def test_no_ambiguity(self):
        # LALR resolves a shift/reduce conflict silently, Earley reports each ambiguity as an _ambig node
        earley_parser = load_grammar(parser="earley", ambiguity="explicit")
        for query in ACCEPTED_QUERIES:
            with self.subTest(query=query):
                tree = earley_parser.parse(query)
                self.assertEqual(list(tree.find_data("_ambig")), [])
