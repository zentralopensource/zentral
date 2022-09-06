import threading
import google.auth
from storages.backends.gcloud import _quote, clean_name, GoogleCloudStorage


class ZentralGoogleCloudStorage(GoogleCloudStorage):
    """A subclass to force the use of the IAM signBlob API

    This allows the signing of blob URLs without having to use a credential file.
    The service account must have the iam.serviceAccounts.signBlob permission."""

    def __init__(self, **settings):
        super().__init__(**settings)
        self._signing_credentials = None
        self._signing_credentials_lock = threading.Lock()

    def url(self, name):
        """
        Return public url or a signed url for the Blob.
        This DOES NOT check for existance of Blob - that makes codes too slow
        for many use cases.

        Overridden to force the use of the IAM signBlob API.
        See https://github.com/googleapis/python-storage/blob/519074112775c19742522158f612b467cf590219/google/cloud/storage/_signing.py#L628  # NOQA
        """
        name = self._normalize_name(clean_name(name))
        blob = self.bucket.blob(name)
        blob_params = self.get_object_parameters(name)
        no_signed_url = (
            blob_params.get('acl', self.default_acl) == 'publicRead' or not self.querystring_auth)

        if not self.custom_endpoint and no_signed_url:
            return blob.public_url
        elif no_signed_url:
            return '{storage_base_url}/{quoted_name}'.format(
                storage_base_url=self.custom_endpoint,
                quoted_name=_quote(name, safe=b"/~"),
            )
        elif not self.custom_endpoint:
            return blob.generate_signed_url(
                expiration=self.expiration,
                version="v4",
                **self._get_signing_kwargs()
            )
        else:
            return blob.generate_signed_url(
                bucket_bound_hostname=self.custom_endpoint,
                expiration=self.expiration,
                version="v4",
                **self._get_signing_kwargs()
            )

    def _get_signing_credentials(self):
        with self._signing_credentials_lock:
            if self._signing_credentials is None or self._signing_credentials.expired:
                credentials, _ = google.auth.default()
                auth_req = google.auth.transport.requests.Request()
                credentials.refresh(auth_req)
                self._signing_credentials = credentials
        return self._signing_credentials

    def _get_signing_kwargs(self):
        credentials = self._get_signing_credentials()
        return {
            "service_account_email": credentials.service_account_email,
            "access_token": credentials.token
        }
