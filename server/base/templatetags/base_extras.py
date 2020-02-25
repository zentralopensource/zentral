from datetime import datetime, timedelta
from importlib import import_module
import logging
import pprint
from django import template
from django.urls import reverse
from django.utils import timezone
from django.utils.html import linebreaks, urlize
from django.utils.safestring import mark_safe
from pygments import lexers, highlight
from pygments.formatters import HtmlFormatter
from django.conf import settings

register = template.Library()

logger = logging.getLogger('zentral.server.base.templatetags.base_extras')

DROPDOWN_LIST = []


@register.inclusion_tag('_main_menu_app_dropdowns.html', takes_context=True)
def main_menu_app_dropdowns(context):
    if not DROPDOWN_LIST:
        for app_name in settings.INSTALLED_APPS:
            app_shortname = app_name.rsplit('.', 1)[-1]
            try:
                url_module = import_module('{}.urls'.format(app_name))
            except ImportError:
                # TODO: ModuleNotFoundError for python >= 3.6
                continue
            main_menu_cfg = getattr(url_module, 'main_menu_cfg', None)
            if not main_menu_cfg:
                logger.info('App %s w/o main menu config', app_name)
                continue
            link_list = []
            dropdown_cfg = {'app_shortname': app_shortname,
                            'title': main_menu_cfg.get('title', None) or app_shortname.title(),
                            'weight': main_menu_cfg.get('weight', 1000)}
            for url_name, anchor_text in main_menu_cfg['items']:
                link_list.append((reverse('{}:{}'.format(app_shortname, url_name)),
                                  anchor_text))
            for extra_context_links in main_menu_cfg.get('extra_context_links', []):
                for section, section_links in context.get(extra_context_links, {}).items():
                    link_list.append((None, section))
                    for link_d in section_links:
                        link_list.append((link_d['url'], link_d['anchor_text']))
            if link_list:
                dropdown_cfg['link_list'] = link_list
                dropdown_cfg['main_link'] = link_list[0][0]
                DROPDOWN_LIST.append(dropdown_cfg)
        DROPDOWN_LIST.sort(key=lambda d: (d['weight'], d['title']))
    for dropdown_cfg in DROPDOWN_LIST:
        dropdown_cfg['is_active'] = context.get(dropdown_cfg['app_shortname'], False) is True
    context['dropdown_list'] = DROPDOWN_LIST
    return context


SETUP_DROPDOWN = []


@register.inclusion_tag('_setup_dropdown.html', takes_context=True)
def setup_dropdown(context):
    if not SETUP_DROPDOWN:
        for app_name in settings.INSTALLED_APPS:
            app_shortname = app_name.rsplit('.', 1)[-1]
            try:
                url_module = import_module('{}.urls'.format(app_name))
            except ImportError:
                # TODO: ModuleNotFoundError for python >= 3.6
                continue
            setup_menu_cfg = getattr(url_module, 'setup_menu_cfg', None)
            if not setup_menu_cfg:
                logger.info('App %s w/o setup menu config', app_name)
                continue
            section_cfg = {'app_shortname': app_shortname,
                           'title': setup_menu_cfg.get('title', None) or app_shortname.title(),
                           'link_list': [],
                           'weight': setup_menu_cfg.get('weight', 1000)}
            for url_name, anchor_text in setup_menu_cfg['items']:
                section_cfg['link_list'].append((reverse('{}:{}'.format(app_shortname, url_name)),
                                                 anchor_text))
            SETUP_DROPDOWN.append(section_cfg)
        SETUP_DROPDOWN.sort(key=lambda d: (d['weight'], d['title']))
    context["active"] = context.get("setup", False)
    context["section_list"] = SETUP_DROPDOWN
    return context


@register.filter(is_safe=True, needs_autoescape=True)
def prettydescription(value, autoescape=True):
    """combine linebreaks and urlize"""
    return mark_safe(linebreaks(urlize(value, nofollow=True, autoescape=autoescape)))


@register.filter()
def pythonprettyprint(val):
    s = pprint.pformat(val)
    lexer = lexers.get_lexer_by_name('python')
    formatter = HtmlFormatter()
    return mark_safe(highlight(s, lexer, formatter))


@register.filter()
def maybetimestamp(val):
    try:
        dt = datetime.utcfromtimestamp(int(val))
    except (OSError, TypeError, ValueError):
        pass
    else:
        now = timezone.now()
        if abs(now - dt) < timedelta(days=5*366):
            return dt
    return val
