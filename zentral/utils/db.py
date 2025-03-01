from django.conf import settings


def get_read_only_database():
    if "ro" in settings.DATABASES:
        return "ro"
    return "default"
