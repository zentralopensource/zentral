from pygments import highlight
from pygments.lexers import SqlLexer
from pygments.formatters import HtmlFormatter
import sqlparse


def format_sql(query):
    if not query:
        return ""
    sql_lexer = SqlLexer()
    html_formatter = HtmlFormatter()
    reindent = len(query) > 80
    query = sqlparse.format(query, reindent=reindent, keyword_case='upper')
    return highlight(query, sql_lexer, html_formatter)
