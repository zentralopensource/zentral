from django import template
from django.utils.html import escape
from django.utils.safestring import mark_safe
from zentral.core.incidents.models import SEVERITY_CHOICES
from zentral.utils.color import text_color_for_background_color

register = template.Library()


@register.simple_tag
def incident_severity(severity, default=""):
    if severity is None:
        return default
    color_dict = {
        300: "ff0000",
        200: "ff9900",
        100: "ffff00",
    }
    color = color_dict.get(severity, "000000")
    style = {'background-color': "#%s" % color,
             'color': "#%s" % text_color_for_background_color(color)}
    if color.upper() in ["FFFFFF", "FFF"]:
        style['border'] = '1px solid grey'
    style_str = ";".join(["%s:%s" % (key, val) for key, val in style.items()])
    return mark_safe(
        '<span class="label" style="%s">%s&nbsp;<i class="fas fa-skull-crossbones"></i></span>' % (
            style_str,
            escape(dict(SEVERITY_CHOICES).get(severity, str(severity)))
        )
    )
