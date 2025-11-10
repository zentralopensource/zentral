import logging
import json
from django import template


register = template.Library()

logger = logging.getLogger('zentral.server.base.templatetags.inclusion_tags')


@register.inclusion_tag('accounts/tasks/_status.html')
def task_status(task):
    return {'task': task}


@register.inclusion_tag('accounts/tasks/_time.html')
def task_time(task):
    time_diff = 0
    try:
        time_diff = task.date_done - task.date_created
    except IndexError:
        pass
    return {'task': task, 'time_diff': time_diff}


@register.inclusion_tag('accounts/tasks/_result.html')
def task_result(task):
    try:
        if isinstance(task.result, (bytes, bytearray)):
            result_json = json.loads(task.result)
            return {'task': task, 'result_json': result_json}
        else:
            return {'task': task, 'result_json': "{}"}
    except IndexError:
        pass

@register.filter
def partition_replace_capitalize(value, partition_char=".", find_char="_", replace_char=" "):
    _, _, last = str(value).rpartition(partition_char)
    return last.replace(find_char, replace_char).title()
