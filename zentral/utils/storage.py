from django.core.files.storage import storages


def file_storage_has_signed_urls():
    # TODO better detection!
    storage_class_name = storages["default"].__class__.__name__
    return storage_class_name in ('S3Storage', 'S3Boto3Storage', 'GoogleCloudStorage', 'ZentralGoogleCloudStorage')
