import logging
import json
from django import template
from django.core.exceptions import ObjectDoesNotExist


register = template.Library()

logger = logging.getLogger('zentral.server.base.templatetags.inclusion_tags')


@register.inclusion_tag('accounts/tasks/_status.html')
def task_status(task):
    return {'task': task}


@register.inclusion_tag('accounts/tasks/_user.html')
def task_user(task):
    user = None
    try:
        user = task.usertask.user
    except ObjectDoesNotExist:
        pass
    return {'task': task, 'user': user}


@register.inclusion_tag('accounts/tasks/_time.html')
def task_time(task):
    time_diff = 0
    if task.date_done and task.date_started:
        time_diff = task.date_done - task.date_started
    return {'task': task, 'time_diff': time_diff}


@register.inclusion_tag('accounts/tasks/_result.html')
def task_result(task, show_result=False):
    result_json = {}
    if isinstance(task.result, (str, bytes, bytearray)):
        result_json = json.loads(task.result)
    return {'task': task, 'result_json': result_json, 'show_result': show_result}


@register.filter
def partition_replace_capitalize(value, partition_char=".", find_char="_", replace_char=" "):
    _, _, last = str(value).rpartition(partition_char)
    return last.replace(find_char, replace_char).title()
