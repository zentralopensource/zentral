import logging
import re

from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import SqlLexer

logger = logging.getLogger("zentral.utils.sql")


# SQL → HTML

def format_sql(query):
    if not query:
        return ""
    sql_lexer = SqlLexer()
    html_formatter = HtmlFormatter(cssclass="highlight")
    query = query.strip()
    return highlight(query, sql_lexer, html_formatter)


# See https://grisha.org/blog/2016/11/14/table-names-from-sql/
def tables_in_query(sql_str):

    # remove the /* */ comments
    q = re.sub(r"/\*[^*]*\*+(?:[^*/][^*]*\*+)*/", "", sql_str)

    # remove whole line -- and # comments
    lines = [line for line in q.splitlines() if not re.match(r"^\s*(--|#)", line)]

    # remove trailing -- and # comments
    q = " ".join([re.split(r"--|#", line)[0] for line in lines])

    # split on blanks, parens and semicolons
    tokens = re.split(r"[\s)(;]+", q)

    # scan the tokens. if we see a FROM or JOIN, we set the get_next
    # flag, and grab the next one (unless it's SELECT).

    result = set()
    get_next = False
    for tok in tokens:
        if get_next:
            if tok.lower() not in ["", "select"]:
                result.add(tok)
            get_next = False
        get_next = tok.lower() in ["from", "join"]

    return result
