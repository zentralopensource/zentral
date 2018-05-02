from django import template
from django.urls import reverse
from django.utils.html import escape
from django.utils.http import urlencode
from django.utils.safestring import mark_safe
from zentral.contrib.inventory.conf import IOS, LINUX, MACOS, WINDOWS

register = template.Library()


@register.simple_tag
def inventory_tag(tag):
    style = {'background-color': "#%s" % tag.color,
             'color': "#%s" % tag.text_color()}
    if tag.need_border():
        style['border'] = '1px solid grey'
    sty_str = ";".join(["%s:%s" % (key, val) for key, val in style.items()])
    return mark_safe('<span class="label" style="%s">%s</span>' %
                     (sty_str, escape(str(tag))))


@register.simple_tag
def machine_type_icon(meta_machine):
    machine_type = meta_machine.type
    icon = None
    if machine_type == "VM":
        icon = "cube"
    elif machine_type:
        icon = machine_type.lower()
    if icon:
        return mark_safe('<i class="fa fa-{}" aria-hidden="true"></i>'.format(icon))
    return ""


@register.simple_tag
def machine_platform_icon(meta_machine):
    machine_platform = meta_machine.platform
    icon = None
    if machine_platform in {MACOS, IOS}:
        icon = "apple"
    elif machine_platform == LINUX:
        icon = "linux"
    elif machine_platform == WINDOWS:
        icon = "windows"
    if icon:
        return mark_safe('<i class="fa fa-{}" aria-hidden="true"></i>'.format(icon))
    return ""


@register.simple_tag
def sha_256_link(sha_256):
    if sha_256:
        url = "{}?{}".format(reverse("inventory:macos_apps"),
                             urlencode({"sha_256": sha_256}))
        return mark_safe('<a href="{}">{}</a>'.format(url, sha_256))
    else:
        return "-"
