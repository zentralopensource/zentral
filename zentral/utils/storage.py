from django.core.files.storage import get_storage_class


def file_storage_has_signed_urls():
    # TODO better detection!
    return get_storage_class().__name__ in ('S3Boto3Storage', 'GoogleCloudStorage', 'ZentralGoogleCloudStorage')
