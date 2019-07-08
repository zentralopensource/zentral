from django import template
from django.urls import reverse
from django.utils.html import escape
from django.utils.http import urlencode
from django.utils.safestring import mark_safe
from zentral.contrib.inventory.conf import IOS, IPADOS, LINUX, MACOS, TVOS, WINDOWS
from zentral.contrib.inventory.models import MetaMachine
from zentral.utils.color import text_color_for_background_color

register = template.Library()


@register.simple_tag
def base_inventory_tag(display_name, color):
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
    if icon:
        return mark_safe('<i class="fab fa-{}" aria-hidden="true"></i>'.format(icon))
    return ""


@register.simple_tag
def machine_platform_icon(meta_machine):
    machine_platform = meta_machine.platform
    return base_machine_platform_icon(machine_platform)


@register.simple_tag
def sha_256_link(sha_256):
    if sha_256:
        url = "{}?{}".format(reverse("inventory:macos_apps"),
                             urlencode({"sha_256": sha_256}))
        return mark_safe('<a href="{}">{}</a>'.format(url, sha_256))
    else:
        return "-"


@register.simple_tag
def machine_url(serial_number):
    return reverse("inventory:machine", args=(MetaMachine(serial_number).get_urlsafe_serial_number(),))
