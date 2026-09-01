import logging

from django.core.exceptions import ValidationError
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import SqlLexer
import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

logger = logging.getLogger("zentral.utils.sql")


class SQLParseError(Exception):
    # only the position of the error is kept. the sqlglot descriptions are internal prose that
    # changes between releases, and they tell a user no more than the position does.
    def __init__(self, line=None, col=None):
        self.line = line
        self.col = col
        if line is None:
            super().__init__("Could not parse the SQL query.")
        else:
            super().__init__(f"Could not parse the SQL query at line {line}, column {col}.")


# SQL → HTML

def format_sql(query):
    if not query:
        return ""
    sql_lexer = SqlLexer()
    html_formatter = HtmlFormatter(cssclass="highlight sql")
    query = query.strip()
    return highlight(query, sql_lexer, html_formatter)


# SQL → table names

def extract_tables(sql):
    # osquery runs SQLite
    try:
        tree = sqlglot.parse_one(sql, read="sqlite")
    except SqlglotError as e:
        # a parse error carries the position of the bad token, a tokenizer error carries none
        errors = getattr(e, "errors", None) or [{}]
        raise SQLParseError(errors[0].get("line"), errors[0].get("col")) from e
    # a CTE is defined by the query itself, it is not a table the query reads
    cte_names = {cte.alias_or_name.lower() for cte in tree.find_all(exp.CTE)}
    # sqlglot wraps a function call in FROM, json_each() for example, in a table with no name
    return sorted({table.name.lower() for table in tree.find_all(exp.Table) if table.name} - cte_names)


def extract_tables_or_empty(sql):
    try:
        return extract_tables(sql)
    except SQLParseError as e:
        # the run list re-derives the tables of every row it renders, and it renders rows with
        # SQL that was frozen before Zentral rejected the SQL it cannot parse
        logger.debug("Could not extract the tables of a SQL query. %s", e)
        return []


def validate_sql(value):
    try:
        extract_tables(value)
    except SQLParseError as e:
        raise ValidationError(str(e))
