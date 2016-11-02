from django import template
from django.template.loader import render_to_string

register = template.Library()


@register.simple_tag
def action_probe_config(action, action_config_d):
    return render_to_string(action.probe_config_template_name,
                            {'action_config_d': action.get_probe_context_action_config_d(action_config_d)})
