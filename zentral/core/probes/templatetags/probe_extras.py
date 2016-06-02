from django import template

register = template.Library()


@register.inclusion_tag('core/probes/_probe_list.html')
def probe_list(probe_list):
    return {"probe_list": probe_list}
