import html
import re

from django.test import SimpleTestCase

from zentral.utils.sql import format_sql, tables_in_query


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


class TablesInQueryTestCase(SimpleTestCase):
    def test_simple_query(self):
        self.assertEqual(tables_in_query("select * from users;"), {"users"})

    def test_join_and_comments(self):
        query = (
            "-- a comment\n"
            "select * from users u /* another comment */\n"
            "join groups g on (u.gid = g.gid)"
        )
        self.assertEqual(tables_in_query(query), {"users", "groups"})
