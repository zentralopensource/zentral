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


@register.simple_tag
def inventory_tag(tag):
    style = {'background-color': "#%s" % tag.color,
             'color': "#%s" % tag.text_color()}
    if tag.need_border():
        style['border'] = '1px solid grey'
    sty_str = ";".join(["%s:%s" % (key, val) for key, val in style.items()])
    return mark_safe('<span class="label" style="%s">%s</span>' %
                     (sty_str, str(tag)))
