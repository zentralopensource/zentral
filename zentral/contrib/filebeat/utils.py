from importlib import import_module
from urllib.parse import urlparse
import yaml
from zentral.conf import settings


def build_filebeat_yml(configuration):
    fb_cfg = {
        "path": {"home": "/usr/local/zentral/filebeat"},
        "output": {
            "logstash": {
                "hosts": ["{}:5044".format(urlparse(settings["api"]["tls_hostname"]).netloc)],
                "ssl": {
                    "enable": True,
                    "certificate": "/usr/local/zentral/filebeat/client.crt",
                    "key": "/usr/local/zentral/filebeat/client.key",
                },
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
    if settings["api"].get("distribute_tls_server_certs", True):
        fb_cfg["output"]["logstash"]["ssl"]["certificate_authorities"] = [
            "/usr/local/zentral/tls_server_certs.crt",
        ]
    for app in settings['apps']:
        try:
            filebeat_module = import_module("{}.filebeat".format(app))
        except ImportError:
            pass
        else:
            for input_cfg in getattr(filebeat_module, "inputs")(configuration):
                fb_cfg["filebeat"]["inputs"].append(input_cfg)
    return yaml.dump(fb_cfg)
