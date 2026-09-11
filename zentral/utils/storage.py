from datetime import timedelta
from django.core.files.storage import storages, InvalidStorageError


def file_storage_has_signed_urls(storage=None):
    if storage is None:
        storage = storages["default"]
    # TODO better detection!
    storage_class_name = storage.__class__.__name__
    return storage_class_name in ('S3Storage', 'S3Boto3Storage', 'GoogleCloudStorage', 'ZentralGoogleCloudStorage')


def file_storage_signed_url_expiration(storage=None):
    if storage is None:
        storage = storages["default"]
    if not file_storage_has_signed_urls(storage) or not getattr(storage, "querystring_auth", True):
        return None
    # GCS
    expiration = getattr(storage, "expiration", None)
    if isinstance(expiration, timedelta):
        return expiration
    # S3
    querystring_expire = getattr(storage, "querystring_expire", None)
    if querystring_expire:
        return timedelta(seconds=int(querystring_expire))
    return None


def select_dist_storage():
    try:
        return storages["dist"]
    except InvalidStorageError:
        return storages["default"]
