import logging
import yaml
from zentral.core.exceptions import ImproperlyConfigured

logger = logging.getLogger('zentral.core.probes')


class BaseProbe(object):
    def __init__(self, source):
        self.source = source
        self.pk = source.pk
        self.status = source.status
        self.name = source.name
        self.slug = source.slug
        self.description = source.description
        self.actions = []
        err_list = self.full_check()
        if err_list:
            raise ImproperlyConfigured("Invalid probe body", err_list)

    def full_check(self):
        err_list = []
        try:
            self.probe_d = yaml.load(self.source.body)
        except yaml.parser.ParserError:
            err_list.append("Could not parse probe source body")
        if not isinstance(self.probe_d, dict):
            err_list.append("Probe body should be a hash/dict")
        else:
            if "name" in self.probe_d:
                err_list.append("name key in probe body")
            if "description" in self.probe_d:
                err_list.append("description key in probe body")
            actions = self.probe_d.pop("actions", {})
            if not isinstance(actions, dict):
                err_list.append("actions section is not a hash/dict")
            else:
                # TODO import loop !!!
                from zentral.core.actions import actions as available_actions
                for action_name, action_config_d in actions.items():
                    try:
                        self.actions.append((available_actions[action_name],
                                             action_config_d))
                    except KeyError:
                        err_list.append("unknown action %s" % action_name)
                    if action_config_d is not None and not isinstance(action_config_d, dict):
                        print(action_config_d)
                        err_list.append("action {} configuration is not a dict".format(action_name))
            filters = self.probe_d.get("filters", {})
            if not isinstance(filters, dict):
                err_list.append("filters section is not a hash/dict")
            else:
                for filter_section_name in ("inventory", "metadata", "payload"):
                    filter_section = filters.get(filter_section_name, [])
                    if not isinstance(filter_section, list):
                        err_list.append("{} filter section is not a list".format(filter_section_name))
                    else:
                        for filter_item in filter_section:
                            if not isinstance(filter_item, dict):
                                err_list.append(
                                    "{} filter section list contains non dict items".format(
                                        filter_section_name
                                    )
                                )
                            else:
                                for key, val in filter_item.items():
                                    if isinstance(val, list):
                                        if not all(isinstance(s, (int, str)) for s in val):
                                            err_list.append(
                                                "{} test in {} filter section is not a list of str or int".format(
                                                    key, filter_section_name
                                                )
                                            )
                                    elif not isinstance(val, str):
                                        err_list.append(
                                            "{} test in {} filter section is not a list of str or a str".format(
                                                key, filter_section_name
                                            )
                                        )
                        setattr(self, "{}_filters".format(filter_section_name), filter_section)
        if not err_list:
            err_list = self.check()
        return err_list

    def check(self):
        return []

    def get_probe_links(self):
        return []

    def get_extra_context(self):
        return {}

probe_classes = []


def register_probe_class(probe_cls):
    if probe_cls in probe_classes:
        raise ImproperlyConfigured('Probe class "{}" already registered'.format(probe_cls))
    logger.debug('Probe class "%s" registered', probe_cls)
    probe_classes.append(probe_cls)


def load_probe(source):
    for probe_cls in probe_classes:
        try:
            return probe_cls(source)
        except ValueError:
            pass
    return BaseProbe(source)
