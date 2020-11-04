import os
from zentral.core.exceptions import ImproperlyConfigured
from .utils import find_conf_file, load_config_file

ZENTRAL_CONF_DIR_ENV_VAR = "ZENTRAL_CONF_DIR"


__all__ = ['contact_groups', 'settings', 'user_templates_dir']


def get_conf_dir():
    conf_dir = os.environ.get(ZENTRAL_CONF_DIR_ENV_VAR)
    if not conf_dir:
        conf_dir = os.path.realpath(os.path.join(os.path.dirname(__file__),
                                    "../../conf"))
    if os.path.exists(conf_dir):
        return conf_dir
    else:
        raise ImproperlyConfigured('Conf dir could not be found.')


conf_dir = get_conf_dir()


# the user can override the default templates
# by putting correctly named templates in the
# following dir

user_templates_dir = os.path.join(conf_dir, 'templates')


settings = load_config_file(find_conf_file(conf_dir, "base"))

# add default apps
for app in ["zentral.core.incidents", "zentral.core.probes"]:
    settings.setdefault('apps', {})[app] = {}


def load_contact_groups(conf_dir):
    # TODO : optimize !!!
    contact_groups = {}
    contact_filepath = find_conf_file(conf_dir, "contacts", required=False)
    if not contact_filepath:
        return contact_groups
    for contact_d in load_config_file(contact_filepath):
        groups = contact_d.pop('groups')
        for group in groups:
            contact_groups.setdefault(group, []).append(contact_d)
    return contact_groups


contact_groups = load_contact_groups(conf_dir)
