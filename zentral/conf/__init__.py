import json
import os
import yaml
from zentral.core.exceptions import ImproperlyConfigured

ENVIRONMENT_VARIABLE = "ZENTRAL_CONF_DIR"

__all__ = ['contact_groups', 'probes', 'settings', 'user_templates_dir']


def get_conf_dir():
    conf_dir = os.environ.get(ENVIRONMENT_VARIABLE)
    if not conf_dir:
        conf_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../conf"))
    if os.path.exists(conf_dir):
        return conf_dir
    else:
        raise ImproperlyConfigured('Conf dir could not be found.')


conf_dir = get_conf_dir()

# the user can override the default templates
# by putting correctly named templates in the
# following dir

user_templates_dir = os.path.join(conf_dir, 'templates')


def find_conf_file(conf_dir, basename, required=True):
    filepaths = [os.path.join(conf_dir, "{}{}".format(basename, ext)) for ext in [".json", ".yml"]]
    found_files = [f for f in filepaths if os.path.exists(f)]
    if not found_files:
        if required:
            raise ImproperlyConfigured('{} is required'.format(' or '.join(filepaths)))
        else:
            return None
    elif len(found_files) == 2:
        raise ImproperlyConfigured('{} both present: conflict'.format(' and '.join(filepaths)))
    else:
        return found_files[0]


def load_config_file(filepath):
    root, ext = os.path.splitext(filepath)
    if not ext:
        raise ImproperlyConfigured("File {} without extension".format(filepath))
    if ext == '.json':
        fileopener = json.load
        filetype = "JSON"
    elif ext == '.yml':
        fileopener = yaml.load
        filetype = "YAML"
    else:
        raise ImproperlyConfigured("Unknown extension {} of file {}".format(ext, filepath))
    try:
        with open(filepath) as f:
            return fileopener(f)
    except (ValueError, yaml.YAMLError):
        raise ImproperlyConfigured("{} error in file {}".format(filetype, filepath)) from None
    except Exception as e:
        raise ImproperlyConfigured(str(e)) from None


settings = load_config_file(find_conf_file(conf_dir, "base"))


def load_probes(settings, conf_dir):
    probes = {}
    probes_dir = os.path.join(conf_dir, "probes")
    if not os.path.isdir(probes_dir):
        return probes
    for filename in os.listdir(probes_dir):
        if filename.endswith('.json') or filename.endswith('.yml'):
            probe_d = load_config_file(os.path.join(probes_dir, filename))
            probes[probe_d['name']] = probe_d
    return probes


probes = load_probes(settings, conf_dir)


def inventory_filtered_probes(mbu_ids, tag_ids, probes_to_filter=None):
    """Return the probes matching meta business units id and tag ids.

    By default filter all the probes. Can be restricted to only a subset of the probes."""
    if probes_to_filter is None:
        probes_to_filter = probes.values()
    tag_ids = set(tag_ids)
    mbu_ids = set(mbu_ids)
    filtered_probes = []
    for probe in probes_to_filter:
        try:
            inventory_filters = probe['filters']['inventory']
        except KeyError:
            filtered_probes.append(probe)
            continue
        if not inventory_filters:
            filtered_probes.append(probe)
            continue
        for inventory_filter in inventory_filters:
            f_tag_ids = set(int(tag_id) for tag_id in inventory_filter.get('tags', []))
            if f_tag_ids and not f_tag_ids & tag_ids:
                # filter on tags but no intersection with the given tags
                continue
            f_mbu_ids = set(int(mbu_id) for mbu_id in inventory_filter.get('business_units', []))
            if f_mbu_ids and not f_mbu_ids & mbu_ids:
                # filter on business units but not intersection with the given business units
                continue
            # both tests above passed. Match.
            filtered_probes.append(probe)
            # no need to check the other filters (OR)
            break
    return filtered_probes


def machine_probes(machine, probes_to_filter=None):
    """Return the probes that are available for a machine.

    By default filter all the probes. Can be restricted to only a subset of the probes."""
    mbu_ids = [mbu.id for mbu in machine.meta_business_units()]
    tag_ids = [tag.id for tag in machine.tags()]
    return inventory_filtered_probes(mbu_ids, tag_ids, probes_to_filter)


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
