from django import template
from django.utils.html import escape
from django.utils.safestring import mark_safe
from zentral.core.incidents.models import Severity
from zentral.utils.color import text_color_for_background_color


register = template.Library()


@register.simple_tag
def incident_severity(severity, default=""):
    if severity is None:
        return default
    color_dict = {
        300: "ff0000",
        200: "ff9900",
        100: "DDDD00",
    }
    color = color_dict.get(severity, "000000")
    style = {'background-color': "#" + color,
             'color': "#" + text_color_for_background_color(color)}
    if color.upper() in ["FFFFFF", "FFF"]:
        style['border'] = '1px solid grey'
    style_str = ";".join([f"{key}:{val}" for key, val in style.items()])
    try:
        severity_display = escape(str(Severity(severity)))
    except ValueError:
        severity_display = escape(str(severity))
    return mark_safe(
        f'<span class="label rounded p-1" style="{style_str}">'
        f'{severity_display}&nbsp;<i class="fas fa-skull-crossbones"></i>'
        '</span>'
    )
