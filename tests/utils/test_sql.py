import html
import re

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from zentral.utils.sql import SQLParseError, extract_tables, extract_tables_or_empty, format_sql, validate_sql


def html_to_text(highlighted):
    return html.unescape(re.sub(r"<[^>]+>", "", highlighted)).strip("\n")


class FormatSQLTestCase(SimpleTestCase):
    def test_empty_query(self):
        self.assertEqual(format_sql(""), "")
        self.assertEqual(format_sql(None), "")

    def test_short_single_line_query_not_formating(self):
        text = html_to_text(format_sql("select * from users;"))
        self.assertEqual(text, "select * from users;")
        text = html_to_text(format_sql("SELECT * FROM users;"))
        self.assertEqual(text, "SELECT * FROM users;")

    def test_multi_line_query_kept_verbatim(self):
        query = (
            "with expected_versions(name, version) as (\n"
            "  values ('first_package', '0.1.2'),\n"
            "         ('second_package', '3.4.5'),\n"
            "         ('third_package', '6.7.8')\n"
            ")\n"
            "select * from npm_packages\n"
            "join expected_versions using (name, version);"
        )
        self.assertEqual(html_to_text(format_sql(query)), query)

    def test_multi_line_query_stripped(self):
        query = "select *\nfrom users;"
        self.assertEqual(html_to_text(format_sql("\n" + query + "\n")), query)


class ExtractTablesTestCase(SimpleTestCase):
    def test_simple_query(self):
        self.assertEqual(extract_tables("select * from users;"), ["users"])

    def test_no_table(self):
        self.assertEqual(extract_tables("select 'OK' as ztl_status;"), [])

    def test_result_sorted(self):
        self.assertEqual(
            extract_tables("select * from users u join groups g on (u.gid = g.gid) join apps a"),
            ["apps", "groups", "users"]
        )

    def test_table_names_folded_to_lower_case(self):
        self.assertEqual(extract_tables("SELECT * FROM CARVES;"), ["carves"])

    def test_comments_ignored(self):
        query = (
            "-- a comment\n"
            "select * from users u /* another comment */\n"
            "join groups g on (u.gid = g.gid)"
        )
        self.assertEqual(extract_tables(query), ["groups", "users"])

    # osquery has tables named after SQL keywords
    def test_keyword_table_names(self):
        self.assertEqual(
            extract_tables("select * from time, groups, file, hash, users;"),
            ["file", "groups", "hash", "time", "users"]
        )

    def test_cte_not_a_table(self):
        query = (
            "with expected_versions(name, version) as (values ('first_package', '0.1.2'))\n"
            "select * from npm_packages join expected_versions using (name, version);"
        )
        self.assertEqual(extract_tables(query), ["npm_packages"])

    def test_union_all(self):
        self.assertEqual(
            extract_tables("select pid from processes union all select pid from process_open_sockets;"),
            ["process_open_sockets", "processes"]
        )

    def test_subquery_in_from(self):
        self.assertEqual(
            extract_tables("select * from (select uid from users) u join groups g using (gid);"),
            ["groups", "users"]
        )

    # the queries below come from the official osquery packs. the regex this function replaced
    # dropped a table in each of them, always one that follows a comma in the FROM clause. it
    # read the sub query of the XcodeGhost query correctly.
    def test_pack_comma_join_with_aliases(self):
        query = (
            "select liu.*, p.name, p.cmdline, p.cwd, p.root "
            "from logged_in_users liu, processes p where liu.pid = p.pid;"
        )
        self.assertEqual(extract_tables(query), ["logged_in_users", "processes"])

    def test_pack_comma_join(self):
        self.assertEqual(extract_tables("select * from time, osquery_info;"), ["osquery_info", "time"])

    def test_pack_comma_join_with_keyword_table(self):
        query = (
            "select i.*, p.resident_size, p.user_time, p.system_time, time.minutes as counter "
            "from osquery_info i, processes p, time where p.pid = i.pid;"
        )
        self.assertEqual(extract_tables(query), ["osquery_info", "processes", "time"])

    def test_pack_subquery_joined_with_keyword_table(self):
        query = (
            "select * from ("
            "  select apps.bundle_short_version as xcode_version, apps.path as xcode_path,"
            "         file.path, file.type as file_type"
            "  from apps, file"
            "  where apps.bundle_name='Xcode' and"
            "        file.path like (apps.path || '/Contents/Developer/Platforms/%/Developer/SDKs/Library/%%')"
            ") join hash using (path) where file_type = 'regular';"
        )
        self.assertEqual(extract_tables(query), ["apps", "file", "hash"])

    def test_pack_comma_join_with_hash(self):
        query = (
            "select h.md5, h.sha1, s.name, s.module_path from services s, hash h "
            "where h.path = s.module_path and s.module_path like '%GeeSetup_x86%';"
        )
        self.assertEqual(extract_tables(query), ["hash", "services"])

    # sqlglot wraps a function call in FROM in a table node with an empty name
    def test_function_in_from_not_a_table(self):
        self.assertEqual(extract_tables("select key from users, json_each(users.uid);"), ["users"])

    def test_only_a_function_in_from(self):
        self.assertEqual(extract_tables("select * from json_each('[1, 2]');"), [])

    def test_invalid_sql(self):
        with self.assertRaises(SQLParseError) as cm:
            extract_tables("changed sql line;")
        self.assertEqual(cm.exception.line, 1)
        self.assertEqual(cm.exception.col, 16)
        self.assertEqual(str(cm.exception), "Could not parse the SQL query at line 1, column 16.")

    # sqlglot raises without a position when it parses nothing at all
    def test_empty_sql(self):
        with self.assertRaises(SQLParseError) as cm:
            extract_tables("")
        self.assertIsNone(cm.exception.line)
        self.assertIsNone(cm.exception.col)
        self.assertEqual(str(cm.exception), "Could not parse the SQL query.")

    # a tokenizer error is not a parse error, and it carries no position
    def test_unterminated_string(self):
        with self.assertRaises(SQLParseError) as cm:
            extract_tables("select * from users where name = 'zen")
        self.assertIsNone(cm.exception.line)
        self.assertEqual(str(cm.exception), "Could not parse the SQL query.")

    # sqlglot repeats the offending SQL with ANSI escapes on the lines after its own message
    def test_error_message_is_a_single_clean_line(self):
        with self.assertRaises(SQLParseError) as cm:
            extract_tables("not sql at all")
        message = str(cm.exception)
        self.assertEqual(message, "Could not parse the SQL query at line 1, column 14.")
        self.assertNotIn("\n", message)
        self.assertNotIn("\x1b", message)


class ExtractTablesOrEmptyTestCase(SimpleTestCase):
    def test_valid_sql(self):
        self.assertEqual(extract_tables_or_empty("select * from users;"), ["users"])

    def test_invalid_sql(self):
        with self.assertLogs("zentral.utils.sql", level="DEBUG") as cm:
            self.assertEqual(extract_tables_or_empty("changed sql line;"), [])
        self.assertEqual(
            cm.output,
            ["DEBUG:zentral.utils.sql:Could not extract the tables of a SQL query. "
             "Could not parse the SQL query at line 1, column 16."]
        )

    # the run list re-derives the tables of every row it renders. an ERROR for each row of SQL
    # frozen before Zentral rejected the SQL it cannot parse would repeat on every page view.
    def test_invalid_sql_not_logged_as_an_error(self):
        with self.assertNoLogs("zentral.utils.sql", level="INFO"):
            self.assertEqual(extract_tables_or_empty("changed sql line;"), [])


class ValidateSQLTestCase(SimpleTestCase):
    def test_valid_sql(self):
        self.assertIsNone(validate_sql("select * from users;"))

    def test_invalid_sql(self):
        with self.assertRaises(ValidationError) as cm:
            validate_sql("changed sql line;")
        self.assertEqual(cm.exception.messages, ["Could not parse the SQL query at line 1, column 16."])

    def test_invalid_sql_without_position(self):
        with self.assertRaises(ValidationError) as cm:
            validate_sql("select * from users where name = 'zen")
        self.assertEqual(cm.exception.messages, ["Could not parse the SQL query."])
