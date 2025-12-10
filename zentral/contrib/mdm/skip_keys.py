import os.path
import yaml
from django.utils.functional import SimpleLazyObject


def load_yaml():
    return yaml.safe_load(
        open(os.path.join(os.path.dirname(__file__), "schema_data/other/skipkeys.yaml"), "r")
    )


def build_skippable_setup_panes():
    skipkeys = load_yaml()
    skippable_setup_panes = []
    for payloadkey in skipkeys["payloadkeys"]:
        label_items = [payloadkey["title"]]
        supported_os = []
        for platform in sorted(payloadkey.get("supportedOS", {}).keys()):
            try:
                from_version = payloadkey["supportedOS"][platform]["introduced"]
            except KeyError:
                supported_os.append(platform)
            else:
                if from_version != 'n/a':
                    supported_os.append(f"{platform} ≥ {from_version}")
        if supported_os:
            label_items.append(", ".join(supported_os))
        skippable_setup_panes.append((payloadkey["key"], " ‐ ".join(label_items)))
    return skippable_setup_panes


skippable_setup_panes = SimpleLazyObject(build_skippable_setup_panes)
