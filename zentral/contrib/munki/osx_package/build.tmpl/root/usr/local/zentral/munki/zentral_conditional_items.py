#!/usr/local/munki/munki-python
import plistlib


def update_conditional_items():
    try:
        with open("/usr/local/zentral/munki/facts.plist", "rb") as f:
            zentral_facts = plistlib.load(f)
    except FileNotFoundError:
        return
    dest = "/Library/Managed Installs/ConditionalItems.plist"
    items = {}
    try:
        with open(dest, "rb") as f:
            items = plistlib.load(f)
    except FileNotFoundError:
        pass
    items.update(zentral_facts)
    with open(dest, "wb") as f:
        plistlib.dump(items, f)


if __name__ == "__main__":
    update_conditional_items()
