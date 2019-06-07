from collections import OrderedDict
from importlib import import_module
from urllib.parse import urlparse
import yaml
from zentral.conf import settings


class AvailableInputs(object):
    def __init__(self):
        self._inputs = None

    def _load(self):
        if self._inputs is None:
            self._inputs = OrderedDict()
            for app in settings['apps']:
                try:
                    filebeat_module = import_module("{}.filebeat".format(app))
                except ImportError:
                    pass
                else:
                    self._inputs[app] = getattr(filebeat_module, "inputs")

    def iter_forms(self):
        self._load()
        for app, app_inputs in self._inputs.items():
            for input_key, input_d in app_inputs.items():
                yield (app,
                       "{}.{}".format(app, input_key),  # unique prefix
                       input_d["name"],
                       input_d["form_class"])

    def forms_for_context(self, inputs=None):
        input_forms = OrderedDict()
        for app, prefix, name, form_class in self.iter_forms():
            if app not in input_forms:
                input_forms[app] = {"name": app.split(".")[-1].replace("_", " ").title(),
                                    "forms": OrderedDict()}
            if inputs and prefix in inputs:
                data = {}
                for k, v in inputs[prefix].items():
                    data["{}-{}".format(prefix, k)] = v
            else:
                data = None
            input_forms[app]["forms"][prefix] = {"name": name,
                                                 "form": form_class(data, prefix=prefix)}
        return [(app_d["name"],
                 [(form_d["name"], form_d["form"]) for form_d in app_d["forms"].values()])
                for app_d in input_forms.values()]

    def serialized_inputs(self, post_data):
        forms = OrderedDict()
        serialized_inputs = None
        errors = False
        for _, prefix, name, form_class in self.iter_forms():
            if prefix not in post_data:
                continue
            form = form_class(post_data, prefix=prefix)
            if not form.is_valid():
                errors = True
            forms[prefix] = {"name": name,
                             "form": form}
        if not errors:
            serialized_inputs_d = {}
            for prefix, form_d in forms.items():
                form = form_d["form"]
                serialized_inputs_d[prefix] = form.cleaned_data
            serialized_inputs = serialized_inputs_d
        return ([(prefix, form_d["name"], form_d["form"]) for prefix, form_d in forms.items()],
                serialized_inputs)

    def iter_filebeat_inputs(self, inputs):
        for _, prefix, _, form_class in self.iter_forms():
            if prefix in inputs:
                form = form_class(inputs[prefix])
                form.is_valid()
                filebeat_input = form.get_filebeat_input()
                filebeat_input.update({
                    "fields": {
                        "zentral_log_type": prefix
                    },
                    "fields_under_root": True,
                })
                yield filebeat_input


available_inputs = AvailableInputs()


def build_filebeat_yml(configuration, certificate=None, key=None, certificate_authority=None):
    ssl = {"enable": True}
    if certificate:
        ssl["certificate"] = certificate
    if key:
        ssl["key"] = key
    fb_cfg = {
        "output": {
            "logstash": {
                "hosts": ["{}:5044".format(urlparse(settings["api"]["tls_hostname"]).netloc)],
                "ssl": ssl,
            }
        },
        "processors": [
            {"add_host_metadata": None},
            {"add_cloud_metadata": None},
        ],
        "filebeat": {
            "inputs": [
            ]
        }
    }

    # include tls certs?
    if settings["api"].get("distribute_tls_server_certs", True) and certificate_authority:
        fb_cfg["output"]["logstash"]["ssl"]["certificate_authorities"] = [
            certificate_authority,
        ]

    # add configured filebeat input
    for filebeat_input in available_inputs.iter_filebeat_inputs(configuration.inputs):
        fb_cfg["filebeat"]["inputs"].append(filebeat_input)

    return yaml.dump(fb_cfg)
