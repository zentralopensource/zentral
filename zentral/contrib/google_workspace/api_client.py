import json
import uuid
import logging
from typing import Callable
from django.core.cache import cache
from django.urls import reverse
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from zentral.conf import settings
from .models import Connection


logger = logging.getLogger('zentral.contrib.google_workspace.api_client')


class APIClientError(Exception):
    pass


class APIClient:
    oauth2_state_cache_key_prefix = "gcw-oauth2-state-"
    scopes = [
        "https://www.googleapis.com/auth/admin.directory.group.readonly",
        "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
    ]

    def __init__(self, connection, client_config, user_info):
        self.connection = connection
        self.client_config = client_config
        self.credentials = None
        if user_info:
            try:
                self.credentials = Credentials.from_authorized_user_info(user_info, self.scopes)
            except ValueError:
                logger.exception("Invalid user info. Unable to get credentials")
        self._services = {}

    @classmethod
    def _get_oauth2_state_cache_key(cls, state):
        return f"{cls.oauth2_state_cache_key_prefix}{state}"

    def _get_new_oauth2_state(self):
        state = str(uuid.uuid4())
        cache.set(self._get_oauth2_state_cache_key(state), str(self.connection.pk), 3600)
        return state

    def _get_flow(self):
        return InstalledAppFlow.from_client_config(
            self.client_config,
            scopes=self.scopes,
            redirect_uri="https://{}{}".format(settings["api"]["fqdn"], reverse("google_workspace:redirect")),
        )

    @classmethod
    def from_connection(cls, connection):
        # client config
        client_config = json.loads(connection.get_client_config())
        # user info
        user_info = None
        serialized_user_info = connection.get_user_info()
        if serialized_user_info:
            user_info = json.loads(serialized_user_info)
        return cls(connection, client_config, user_info)

    @classmethod
    def from_oauth2_state(cls, state):
        connection_pk = cache.get(cls._get_oauth2_state_cache_key(state))
        if not connection_pk:
            raise APIClientError("Invalid OAUTH2 state")
        try:
            connection = Connection.objects.get(pk=connection_pk)
        except Connection.DoesNotExist:
            raise APIClientError("Invalid Google Workspace connection")
        return cls.from_connection(connection)

    def is_healthy(self, error_message_callback: Callable[[str], None] = None) -> bool:
        try:
            self.dir_svc().groups().list(customer="my_customer", maxResults=1).execute()
            return True
        except Exception as err:
            if isinstance(err, HttpError):
                if err.resp.status == 404:
                    return True

            message = f"Authorization needed for {self.connection} connection."
            logger.info(message, exc_info=True)
            if (error_message_callback):
                error_message_callback(message)
        return False

    def start_flow(self):
        return self._get_flow().authorization_url(state=self._get_new_oauth2_state())[0]

    def complete_authorization(self, code):
        flow = self._get_flow()
        flow.fetch_token(code=code)
        self.credentials = flow.credentials
        self.connection.set_user_info(self.credentials.to_json())
        self.connection.save()

    def _get_service(self, sdk, api):
        key = (sdk, api)
        service = self._services.get(key)
        if service is None:
            if not self.credentials:
                raise APIClientError("No credentials for Google Workspace Connection")
            service = build(sdk, api, credentials=self.credentials)
            self._services[key] = service
        return service

    def dir_svc(self):
        return self._get_service("admin", "directory_v1")

    def get_group(self, group_key):
        try:
            return self.dir_svc().groups().get(groupKey=group_key).execute()
        except HttpError as err:
            if err.resp.status == 404:
                return
            raise

    def iter_groups(self):
        page_token = None
        while True:
            response = self.dir_svc().groups().list(customer="my_customer", pageToken=page_token).execute()
            yield from response.get("groups", [])
            page_token = response.get("nextPageToken")
            if not page_token:
                break

    def iter_group_members(self, group_key):
        page_token = None
        while True:
            response = self.dir_svc().members().list(groupKey=group_key, pageToken=page_token).execute()
            yield from response.get("members", [])
            page_token = response.get("nextPageToken")
            if not page_token:
                break


def validate_group_in_connection(
        connection: Connection, group_email: str, error_supplier: Callable[[], Exception]) -> None:
    api_client = APIClient.from_connection(connection)
    if group_email not in [group["email"] for group in api_client.iter_groups()]:
        raise error_supplier()
