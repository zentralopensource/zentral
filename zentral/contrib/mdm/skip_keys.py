import os.path
import yaml
from django.utils.functional import SimpleLazyObject


def load_yaml():
    return yaml.safe_load(
        open(os.path.join(os.path.dirname(__file__), "schema_data/skipkeys.yaml"), "r")
    )


def build_skippable_setup_panes():
    skipkeys = load_yaml()
    skippable_setup_panes = []
    for payloadkey in skipkeys["payloadkeys"]:
        skippable_setup_panes.append((payloadkey["key"], payloadkey["title"]))
    return skippable_setup_panes


skippable_setup_panes = SimpleLazyObject(build_skippable_setup_panes)
