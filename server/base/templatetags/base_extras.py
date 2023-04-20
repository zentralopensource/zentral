from datetime import datetime, timedelta
from importlib import import_module
import logging
import pprint
from django import template
from django.template.defaultfilters import stringfilter
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import SimpleLazyObject
from django.utils.safestring import mark_safe
from pygments import lexers, highlight
from pygments.formatters import HtmlFormatter
from django.conf import settings
from zentral.utils.time import duration_repr as _duration_repr

register = template.Library()

logger = logging.getLogger('zentral.server.base.templatetags.base_extras')


class MenuConfig:
    def __init__(self, config_attr):
        self.sections = []
        prepared_sections = {}
        for app_name in settings.INSTALLED_APPS:
            app_shortname = app_name.rsplit('.', 1)[-1]
            try:
                url_module = import_module('{}.urls'.format(app_name))
            except ModuleNotFoundError:
                continue
            menu_cfg = getattr(url_module, config_attr, None)
            if not menu_cfg:
                logger.debug('App %s w/o %s', app_name, config_attr)
                continue
            title = menu_cfg.get('title', app_shortname.title())
            section_cfg = prepared_sections.setdefault(
                title,
                {'title': title,
                 'link_list': [],
                 # TODO Legacy. Only used for the creation links for the probes, set with a context processor
                 'extra_links_context_keys': menu_cfg.get("extra_context_links", []),
                 'weight': menu_cfg.get('weight', 1000)}
            )
            for item in menu_cfg['items']:
                try:
                    url_name, anchor_text = item
                except ValueError:
                    try:
                        url_name, anchor_text, local_user, permissions = item
                    except ValueError:
                        logger.error("Error in setup menu config for app %s", app_name)
                        continue
                else:
                    local_user = False
                    permissions = None
                section_cfg['link_list'].append((reverse(f"{app_shortname}:{url_name}"), anchor_text,
                                                 local_user, permissions))
        if prepared_sections:
            self.sections = sorted(prepared_sections.values(), key=lambda s: (s['weight'], s['title']))

    @staticmethod
    def _iter_section_links(context, section):
        yield from section["link_list"]
        # TODO Legacy. Only used for the creation links for the probes, set with a context processor
        extra_links_context_keys = section['extra_links_context_keys']
        if extra_links_context_keys:
            if "_cached_extra_context_links" not in section:
                cached_extra_context_links = section.setdefault("_cached_extra_context_links", [])
                for context_key in section.get('extra_links_context_keys', []):
                    for subsection, subsection_links in context.get(context_key, {}).items():
                        cached_extra_context_links.append((None, subsection.title(), False, None))
                        for link_d in subsection_links:
                            cached_extra_context_links.append((
                                str(link_d["url"]), link_d["anchor_text"],
                                link_d.get("local_user", False),
                                link_d.get("permissions")
                            ))
                section["_cached_extra_context_links"] = cached_extra_context_links
            yield from section["_cached_extra_context_links"]

    def get_filtered_sections(self, context):
        request = context.get("request")
        if not request:
            return []
        active = False
        user = request.user
        ras = request.realm_authentication_session
        filtered_sections = []
        for section in self.sections:
            filtered_section = section.copy()
            filtered_section['link_list'] = []
            active_link_length = 0
            active_link = None
            for url, anchor_text, local_user, permissions in self._iter_section_links(context, section):
                # verify local user
                if local_user is True and (user.is_remote or ras.is_remote):
                    continue
                # verify permissions
                if permissions:
                    # model permissions
                    if not user.has_perms(p for p in permissions if "." in p):
                        continue
                    # module permissions
                    if not all(user.has_module_perms(p) for p in permissions if "." not in p):
                        continue
                link_t = [url, anchor_text, False]
                if url and request.path.startswith(url):
                    link_length = len(url)
                    if link_length > active_link_length:
                        active_link_length = link_length
                        active_link = link_t
                filtered_section['link_list'].append(link_t)
            # TODO Legacy, only used to remove the title for the creation links for the probes,
            # if the permissions for the links are not present.
            while filtered_section['link_list']:
                if filtered_section['link_list'][-1][0] is None:
                    del filtered_section['link_list'][-1]
                else:
                    break
            if filtered_section['link_list']:
                if active_link:
                    filtered_section["is_active"] = True
                    active_link[2] = True
                    active = True
                filtered_sections.append(filtered_section)
        return active, filtered_sections


setup_menu_config = SimpleLazyObject(lambda: MenuConfig("setup_menu_cfg"))


@register.inclusion_tag('_setup_dropdown.html', takes_context=True)
def setup_dropdown(context):
    context["active"], context["section_list"] = setup_menu_config.get_filtered_sections(context)
    return context


main_menu_config = SimpleLazyObject(lambda: MenuConfig("main_menu_cfg"))


@register.inclusion_tag('_main_menu_app_dropdowns.html', takes_context=True)
def main_menu_app_dropdowns(context):
    _, context["dropdown_list"] = main_menu_config.get_filtered_sections(context)
    return context


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
    except (OSError, OverflowError, TypeError, ValueError):
        pass
    else:
        now = timezone.now()
        if abs(now - dt) < timedelta(days=5*366):
            return dt
    return val


# see https://stackoverflow.com/a/57022261
@register.filter(is_safe=True)
@stringfilter
def truncatechars_middle(value, arg):
    try:
        ln = int(arg)
    except ValueError:
        return value
    if len(value) <= ln:
        return value
    else:
        return '{}[…]{}'.format(value[:ln//2], value[-((ln+1)//2):])


@register.filter()
def duration_repr(val):
    try:
        return _duration_repr(val)
    except Exception:
        return "-"
