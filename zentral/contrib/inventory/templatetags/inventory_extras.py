import pprint
from django import template
from django.utils.safestring import mark_safe
from pygments import lexers, highlight
from pygments.formatters import HtmlFormatter

register = template.Library()


@register.filter()
def pythonprettyprint(val):
    s = pprint.pformat(val)
    lexer = lexers.get_lexer_by_name('python')
    formatter = HtmlFormatter()
    return mark_safe(highlight(s, lexer, formatter))
