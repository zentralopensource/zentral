from datetime import datetime, timedelta
import logging
import os.path
from azure.core.exceptions import ResourceNotFoundError
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.storage.blob import BlobSasPermissions, BlobServiceClient, generate_blob_sas
from django import forms
from django.http import HttpResponseRedirect
from django.utils.functional import cached_property
from rest_framework import serializers
from zentral.contrib.monolith.exceptions import RepositoryError
from .base import BaseRepository


logger = logging.getLogger("zentral.contrib.monolith.repository_backends.azure")


class AzureRepositoryForm(forms.Form):
    storage_account = forms.CharField()
    container = forms.CharField()
    prefix = forms.CharField(required=False)
    client_id = forms.CharField(required=False)
    tenant_id = forms.CharField(required=False)
    client_secret = forms.CharField(required=False)

    def get_backend_kwargs(self):
        return {k: v for k, v in self.cleaned_data.items() if v}


class AzureRepositorySerializer(serializers.Serializer):
    storage_account = serializers.CharField()
    container = serializers.CharField()
    prefix = serializers.CharField(required=False, allow_blank=True)
    client_id = serializers.CharField(required=False, allow_blank=True)
    tenant_id = serializers.CharField(required=False, allow_blank=True)
    client_secret = serializers.CharField(required=False, allow_blank=True)


class AzureRepository(BaseRepository):
    kwargs_keys = (
        "prefix",
        "storage_account",
        "container",
        "client_id",
        "tenant_id",
        "client_secret",
    )
    encrypted_kwargs_keys = (
        "client_secret",
    )
    form_class = AzureRepositoryForm
    user_delegation_key_validity = timedelta(minutes=15)
    min_user_delegation_key_validity = timedelta(minutes=3)
    signed_url_validity = timedelta(minutes=3)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._user_delegation_key = (None, None)

    def load(self):
        super().load()

        # default prefix
        if not self.prefix:
            self.prefix = ""

        # fixed credential (optional)
        self._credential_kwargs = {}
        for k in ("client_id", "tenant_id", "client_secret"):
            v = getattr(self, k)
            if v:
                self._credential_kwargs[k] = v

    @cached_property
    def _account_url(self):
        return f"https://{self.storage_account}.blob.core.windows.net"

    @cached_property
    def _blob_service_client(self):
        if self._credential_kwargs:
            credential = ClientSecretCredential(**self._credential_kwargs)
        else:
            credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        return BlobServiceClient(
            account_url=self._account_url,
            credential=credential,
        )

    def get_user_delegation_key(self):
        key, expiry = self._user_delegation_key
        now = datetime.utcnow()
        if expiry is None or (expiry - now) < self.min_user_delegation_key_validity:
            expiry = now + self.user_delegation_key_validity
            key = self._blob_service_client.get_user_delegation_key(key_start_time=now, key_expiry_time=expiry)
            self._user_delegation_key = (key, expiry)
        return key

    @cached_property
    def _container_client(self):
        return self._blob_service_client.get_container_client(self.container)

    def _get_resource(self, key, missing_ok=False):
        try:
            return self._container_client.download_blob(os.path.join(self.prefix, key)).readall()
        except ResourceNotFoundError:
            logging_args = ("Could not find blob %s in container %s", key, self.container)
            if missing_ok:
                logger.info(*logging_args)
                return None
            logger.exception(*logging_args)
            raise RepositoryError
        except Exception:
            logger.exception("Could not download blob %s from container %s", key, self.container)
            raise RepositoryError

    def get_all_catalog_content(self):
        return self._get_resource("catalogs/all")

    def get_icon_hashes_content(self):
        return self._get_resource("icons/_icon_hashes.plist", missing_ok=True)

    def iter_client_resources(self):
        prefix = os.path.join(self.prefix, "client_resources/")
        try:
            for blob_name in self._container_client.list_blob_names(name_starts_with=prefix):
                yield blob_name.removeprefix(prefix)
        except Exception:
            logger.exception("Could not list client resources keys in container %s", self.container)
            raise RepositoryError

    def make_munki_repository_response(self, section, name, cache_server=None):
        blob_name = os.path.join(self.prefix, section, name)
        sas = generate_blob_sas(
            account_name=self.storage_account,
            account_key=self.get_user_delegation_key(),
            container_name=self.container,
            blob_name=blob_name,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.utcnow() + self.signed_url_validity
        )
        return HttpResponseRedirect(f"{self._account_url}/{self.container}/{blob_name}?{sas}")
