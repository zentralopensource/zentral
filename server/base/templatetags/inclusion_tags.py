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


@register.filter
def flex_field_width(value):
    """ Given the amount of fields, returns a width to use with flexbox. """
    prefix = "-"
    if value == 1:
        return ""
    elif value == 2:
        return prefix + "8"
    elif value == 3:
        return prefix + "6"
    elif value == 4:
        return prefix + "6"
    elif value == 5:
        return prefix + "5"
    else:
        return prefix + str(value)  # FIXME: probably needs adjustment for more controls


# Buttons

ACTION = {
    'CREATE': {
        'icon': "bi bi-plus-circle",
        'tooltip': "Create",
    },
    'UPDATE': {
        'icon': "bi bi-pencil-square",
        'tooltip': "Edit",
    },
    'DELETE': {
        'icon': "bi bi-trash",
        'tooltip': "Delete",
    },
    'EVENTS': {
        'icon': "bi bi-activity",
        'tooltip': "Browse the Events",
    },
    'DOWNLOAD': {
        'icon': "bi bi-download",
        'tooltip': "Download",
    },
    'LINK': {
        'icon': "bi bi-link-45deg",
        'tooltip': "External Link"
    }

}


@register.inclusion_tag('_button.html')
def button(action, url, tooltip=None, placement="bottom"):
    """ Displays a Button.

    Args:
        action(str): kind of operation to perform (ACTION.keys())
        url (str): a reversible url like "application:action".
        tooltip (string, optional): A tooltip to display. If None, is not displayed.
            Defaults to ACTION[key]['icon'].
        placement (str, optional): Tooltip placement. Defaults to "bottom".
    """
    if action not in ACTION.keys():
        raise ValueError("Wrong action name. Possible names are %s " % (str(ACTION.keys())))

    return {
        'url': url,
        'icon': ACTION[action]['icon'],
        'tooltip': ACTION[action]['tooltip'] if tooltip is None else tooltip,
        'placement': placement,
    }
