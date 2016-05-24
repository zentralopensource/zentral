import os.path
import json
import yaml
from zentral.core.exceptions import ImproperlyConfigured


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
