from importlib import import_module
import logging
from django import template
from django.core.urlresolvers import reverse
from zentral.conf import settings

register = template.Library()

logger = logging.getLogger('zentral.server.base.templatetags.server_extras')

DROPDOWN_LIST = []


@register.inclusion_tag('_main_menu_app_dropdowns.html', takes_context=True)
def main_menu_app_dropdowns(context):
    if not DROPDOWN_LIST:
        for app_name in settings['apps']:
            app_shortname = app_name.rsplit('.', 1)[-1]
            url_module = import_module('{}.urls'.format(app_name))
            main_menu_cfg = getattr(url_module, 'main_menu_cfg', None)
            if not main_menu_cfg:
                logger.warning('App %s w/o main menu config', app_name)
                continue
            dropdown_cfg = {'app_shortname': app_shortname,
                            'title': main_menu_cfg.get('title', None) or app_shortname.title(),
                            'link_list': []}
            for url_name, anchor_text in main_menu_cfg['items']:
                dropdown_cfg['link_list'].append((reverse('{}:{}'.format(app_shortname, url_name)),
                                                  anchor_text))
            if dropdown_cfg['link_list']:
                dropdown_cfg['main_link'] = dropdown_cfg['link_list'][0][0]
            DROPDOWN_LIST.append(dropdown_cfg)
    for dropdown_cfg in DROPDOWN_LIST:
        dropdown_cfg['is_active'] = context.get(dropdown_cfg['app_shortname'], False) is True
    context['dropdown_list'] = DROPDOWN_LIST
    return context
