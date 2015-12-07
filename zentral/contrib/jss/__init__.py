from zentral.conf import settings
from zentral.core.exceptions import ImproperlyConfigured


def get_api_secret(settings):
    try:
        return settings['apps']['zentral.contrib.jss']['api_secret']
    except KeyError:
        raise ImproperlyConfigured("Missing attribute 'api_secret' in jss app settings")

api_secret = get_api_secret(settings)
