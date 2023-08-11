import logging
from django import template


register = template.Library()

logger = logging.getLogger('zentral.server.base.templatetags.inclusion_tags')


@register.inclusion_tag('_created_updated_at.html')
def created_updated_at(object):
    return {'object': object}


@register.inclusion_tag('_pagination.html')
def pagination(next_url, previous_url):
    return {
        'next_url': next_url,
        'previous_url': previous_url,
    }


@register.inclusion_tag('_empty_results.html')
def empty_results(link):
    return {
        'reset_search_link': link,
    }


@register.inclusion_tag('_no_entities.html')
def no_entities(entity_name, link=None):
    return {
        'entity_name': entity_name,
        'create_new_entity_link': link,
    }


@register.filter
def to_str(value):
    return str(value)


@register.filter
def to_int(value):
    return int(value)
