from zentral.conf import settings
from zentral.core.exceptions import ImproperlyConfigured


def get_api_secret(settings):
    try:
        return settings['apps']['zentral.contrib.munki']['api_secret']
    except KeyError:
        raise ImproperlyConfigured("Missing attribute 'api_secret' in munki app settings")

api_secret = get_api_secret(settings)
