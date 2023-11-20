import re
from django import template
from django.template.defaultfilters import unordered_list
from django.urls import reverse
from django.utils.html import escape, conditional_escape
from django.utils.safestring import mark_safe
from zentral.contrib.inventory.conf import (ANDROID, IOS, IPADOS, LINUX, MACOS, TVOS, WINDOWS,
                                            DESKTOP, EC2, MOBILE, SERVER, TABLET, VM, TYPE_CHOICES_DICT)
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
    return mark_safe('<span class="badge" style="%s">%s</span>' % (style_str, escape(display_name)))


@register.simple_tag
def inventory_tag(tag):
    return base_inventory_tag(str(tag), tag.color)


@register.simple_tag
def base_machine_type_icon(machine_type):
    if machine_type not in TYPE_CHOICES_DICT:
        return ""
    icon = None
    if machine_type == DESKTOP:
        icon = "pc-display"
    elif machine_type == EC2:
        icon = "amazon"
    elif machine_type == MOBILE:
        icon = "phone-fill"
    elif machine_type == SERVER:
        icon = "hdd-stack-fill"
    elif machine_type == TABLET:
        icon = "tablet-fill"
    elif machine_type == VM:
        icon = "box"
    elif machine_type:
        icon = machine_type.lower()
    if icon:
        return mark_safe(f'<i class="bi bi-{icon}"></i>')
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
        icon = "ubuntu"
    elif machine_platform == WINDOWS:
        icon = "windows"
    elif machine_platform == ANDROID:
        icon = "android"
    if icon:
        return mark_safe('<i class="bi bi-{}" aria-hidden="true"></i>'.format(icon))
    return ""


@register.simple_tag
def machine_platform_icon(meta_machine):
    machine_platform = meta_machine.platform
    return base_machine_platform_icon(machine_platform)


@register.simple_tag
def machine_url(serial_number):
    return reverse("inventory:machine", args=(MetaMachine(serial_number).get_urlsafe_serial_number(),))


@register.simple_tag
def ec2_instance_link(machine_snapshot):
    ec2_instance_metadata = machine_snapshot.ec2_instance_metadata
    if not ec2_instance_metadata:
        return
    return (
        f"https://{ec2_instance_metadata.region}.console.aws.amazon.com"
        f"/ec2/v2/home?region={ec2_instance_metadata.region}"
        f"#InstanceDetails:instanceId={ec2_instance_metadata.instance_id}"
    )


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
        data += '<dt class="col-sm-3 text-md-end">{}</dt>\n'.format(esc(key))
        val = extra_facts[key]
        if isinstance(val, list):
            val_data = "<ul>\n{}</ul>\n".format(unordered_list(val, autoescape=autoescape))
        else:
            val_data = esc(val)
        data += '<dd class="col-sm-9">\n{}\n</dd>\n'.format(val_data)
    return mark_safe(data)
