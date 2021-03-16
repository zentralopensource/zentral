import plistlib


def fact():
    """
    Returns the Zentral facts, that should have been saved during the preflight
    """
    try:
        with open("/usr/local/zentral/munki/facts.plist", "rb") as f:
            return plistlib.load(f)
    except FileNotFoundError:
        return {}


if __name__ == "__main__":
    print(fact())
