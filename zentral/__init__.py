__version__ = "0.1.0"


def setup():
    """
    Configure the settings and load the apps.
    """
    from zentral.apps import apps
    from zentral.conf import settings
    apps.populate(settings.get('apps', []))
