import re
from django import template
from django.template.defaultfilters import unordered_list
from django.urls import reverse
from django.utils.html import escape, conditional_escape
from django.utils.safestring import mark_safe
from zentral.contrib.inventory.conf import ANDROID, IOS, IPADOS, LINUX, MACOS, TVOS, TYPE_CHOICES_DICT, WINDOWS
from zentral.contrib.inventory.models import MetaMachine
from zentral.utils.color import text_color_for_background_color

register = template.Library()


@register.simple_tag
def base_inventory_tag(display_name, color):
    if not re.match(r'^[0-9a-fA-F]{3,6}$', color):
        color = "FFFFFF"
    style = {'background-color': "#%s" % color,
             'color': "#%s" % text_color_for_background_color(color)}
    if color.upper() in ["FFFFFF", "FFF"]:
        style['border'] = '1px solid grey'
    style_str = ";".join(["%s:%s" % (key, val) for key, val in style.items()])
    return mark_safe('<span class="label" style="%s">%s</span>' % (style_str, escape(display_name)))


@register.simple_tag
def inventory_tag(tag):
    return base_inventory_tag(str(tag), tag.color)


@register.simple_tag
def base_machine_type_icon(machine_type):
    if machine_type not in TYPE_CHOICES_DICT:
        return ""
    icon = None
    if machine_type == "VM":
        icon = "cube"
    elif machine_type:
        icon = machine_type.lower()
    if icon:
        return mark_safe('<i class="fas fa-{}"></i>'.format(icon))
    return ""


@register.simple_tag
def machine_type_icon(meta_machine):
    machine_type = meta_machine.type
    return base_machine_type_icon(machine_type)


@register.simple_tag
def base_machine_platform_icon(machine_platform):
    icon = None
    if machine_platform in {IOS, IPADOS, MACOS, TVOS}:
        icon = "apple"
    elif machine_platform == LINUX:
        icon = "linux"
    elif machine_platform == WINDOWS:
        icon = "windows"
    elif machine_platform == ANDROID:
        icon = "android"
    if icon:
        return mark_safe('<i class="fab fa-{}" aria-hidden="true"></i>'.format(icon))
    return ""


@register.simple_tag
def machine_platform_icon(meta_machine):
    machine_platform = meta_machine.platform
    return base_machine_platform_icon(machine_platform)


@register.simple_tag
def machine_url(serial_number):
    return reverse("inventory:machine", args=(MetaMachine(serial_number).get_urlsafe_serial_number(),))


@register.filter(needs_autoescape=True)
def extra_facts(extra_facts, autoescape=True):
    if autoescape:
        esc = conditional_escape
    else:
        def esc(x):
            return x
    if not extra_facts or not isinstance(extra_facts, dict):
        return mark_safe("")
    data = ""
    for key in sorted(extra_facts.keys()):
        data += "<dt>{}</dt>\n".format(esc(key))
        val = extra_facts[key]
        if isinstance(val, list):
            val_data = "<ul>\n{}</ul>\n".format(unordered_list(val, autoescape=autoescape))
        else:
            val_data = esc(val)
        data += "<dd>\n{}\n</dd>\n".format(val_data)
    return mark_safe(data)
