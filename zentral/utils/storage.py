from django.core.files.storage import storages, InvalidStorageError


def file_storage_has_signed_urls(storage=None):
    if storage is None:
        storage = storages["default"]
    # TODO better detection!
    storage_class_name = storage.__class__.__name__
    return storage_class_name in ('S3Storage', 'S3Boto3Storage', 'GoogleCloudStorage', 'ZentralGoogleCloudStorage')


def select_dist_storage():
    try:
        return storages["dist"]
    except InvalidStorageError:
        return storages["default"]
