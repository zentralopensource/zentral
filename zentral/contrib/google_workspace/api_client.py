import json
import uuid
import logging
from abc import ABC, abstractmethod
from typing import Callable, Iterator
from typing_extensions import Self, override
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


class APIClient(ABC):

    def __init__(self):
        super().__init__()
        self._services = {}

    @classmethod
    def from_connection(cls, connection: Connection) -> Self:
        match connection.type:
            case Connection.Type.OAUTH_ADMIN_SDK:
                return _AdminSDKClient.create_from_connection(connection)
            case Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY:
                return _CloudAPIClient.create_from_connection(connection)

    @classmethod
    def from_oauth2_state(cls, state) -> Self:
        return _AdminSDKClient.create_from_oauth2_state(state)

    @classmethod
    def from_customer_id(cls, connection_name, customer_id) -> Self:
        return _CloudAPIClient(connection_name, customer_id)

    @abstractmethod
    def iter_groups(self) -> Iterator[dict[str, str]]:
        pass

    @abstractmethod
    def iter_group_members(self, group_key: str) -> Iterator[dict[str, str]]:
        pass

    @abstractmethod
    def is_healthy(self, error_message_callback: Callable[[str], None] = None) -> bool:
        pass

    @abstractmethod
    def get_group(self, group_key: str):
        pass

    @abstractmethod
    def _build_service(self, sdk, api):
        pass

    def _get_service(self, sdk, api):
        key = (sdk, api)
        service = self._services.get(key)
        if service is None:
            service = self._build_service(sdk, api)
            self._services[key] = service
        return service


class _AdminSDKClient(APIClient):
    oauth2_state_cache_key_prefix = "gcw-oauth2-state-"
    scopes = [
        "https://www.googleapis.com/auth/admin.directory.group.readonly",
        "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
    ]

    def __init__(self, connection, client_config, user_info):
        super().__init__()
        self.connection = connection
        self.client_config = client_config
        self.credentials = None
        if user_info:
            try:
                self.credentials = Credentials.from_authorized_user_info(user_info, self.scopes)
            except ValueError:
                logger.exception("Invalid user info. Unable to get credentials")

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

    def _dir_svc(self):
        return self._get_service("admin", "directory_v1")

    @classmethod
    def create_from_connection(cls, connection: Connection) -> APIClient:
        # client config
        client_config = json.loads(connection.get_client_config())
        # user info
        user_info = None
        serialized_user_info = connection.get_user_info()
        if serialized_user_info:
            user_info = json.loads(serialized_user_info)
        return cls(connection, client_config, user_info)

    @classmethod
    def create_from_oauth2_state(cls, state) -> APIClient:
        connection_pk = cache.get(cls._get_oauth2_state_cache_key(state))
        if not connection_pk:
            raise APIClientError("Invalid OAUTH2 state")
        try:
            connection = Connection.objects.get(pk=connection_pk)
        except Connection.DoesNotExist:
            raise APIClientError("Invalid Google Workspace connection")
        return cls.from_connection(connection)

    @override
    def iter_groups(self) -> Iterator[dict[str, str]]:
        page_token = None
        while True:
            response = self._dir_svc().groups().list(customer="my_customer", pageToken=page_token).execute()
            yield from response.get("groups", [])
            page_token = response.get("nextPageToken")
            if not page_token:
                break

    @override
    def iter_group_members(self, group_key: str) -> Iterator[dict[str, str]]:
        page_token = None
        while True:
            response = self._dir_svc().members().list(
                groupKey=group_key, includeDerivedMembership=True, pageToken=page_token
            ).execute()
            for member in response.get("members", []):
                if member["type"].upper() == "USER":
                    yield member
            page_token = response.get("nextPageToken")
            if not page_token:
                break

    @override
    def is_healthy(self, error_message_callback: Callable[[str], None] = None) -> bool:
        try:
            self._dir_svc().groups().list(customer="my_customer", maxResults=1).execute()
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

    @override
    def get_group(self, group_key: str):
        try:
            return self._dir_svc().groups().get(groupKey=group_key).execute()
        except HttpError as err:
            if err.resp.status == 404:
                return
            raise

    @override
    def _build_service(self, sdk, api):
        if not self.credentials:
            raise APIClientError("No credentials for Google Workspace Connection")
        return build(sdk, api, credentials=self.credentials)

    def start_flow(self):
        return self._get_flow().authorization_url(state=self._get_new_oauth2_state())[0]

    def complete_authorization(self, code):
        flow = self._get_flow()
        flow.fetch_token(code=code)
        self.credentials = flow.credentials
        self.connection.set_user_info(self.credentials.to_json())
        self.connection.save()


class _CloudAPIClient(APIClient):

    def __init__(self, connection_name: str, customer_id: str):
        super().__init__()
        self.connection_name = connection_name
        self.customer_id = customer_id

    @override
    def is_healthy(self, error_message_callback: Callable[[str], None] = None) -> bool:
        try:
            self._identity_svc().groups().list(parent=f"customers/{self.customer_id}", pageSize=1).execute()
            return True
        except Exception as err:
            if isinstance(err, HttpError):
                if err.resp.status == 404:
                    return True

            message = f"Authorization needed for {self.connection_name} connection."
            logger.info(message, exc_info=True)
            if (error_message_callback):
                error_message_callback(message)
        return False

    @override
    def iter_groups(self) -> Iterator[dict[str, str]]:
        page_token = None
        while True:
            response = self._identity_svc().groups().list(parent=f"customers/{self.customer_id}").execute()
            for group in response.get("groups", []):
                group_key = group["groupKey"]
                email = group_key["id"]
                group["email"] = email

                yield group

            page_token = response.get("nextPageToken")
            if not page_token:
                break

    @override
    def iter_group_members(self, group_key) -> Iterator[dict[str, str]]:
        page_token = None
        while True:
            group_identifier = self._identity_svc().groups().lookup(groupKey_id=group_key).execute()["name"]
            response = self._identity_svc().groups().memberships().searchTransitiveMemberships(
                parent=group_identifier, pageToken=page_token
            ).execute()
            for member in response.get("memberships", []):
                email = member["preferredMemberKey"][0]["id"]
                member["email"] = email
                yield member
            page_token = response.get("nextPageToken")
            if not page_token:
                break

    @override
    def get_group(self, group_key: str):
        try:
            return self._identity_svc().groups().lookup(groupKey_id=group_key).execute()
        except HttpError as err:
            if err.resp.status == 404:
                return
            raise

    @override
    def _build_service(self, sdk, api):
        return build(sdk, api)

    def _identity_svc(self):
        return self._get_service("cloudidentity", "v1")

    @classmethod
    def create_from_connection(cls: Self, connection: Connection) -> APIClient:
        return cls(connection.name, connection.customer_id)


def validate_group_in_connection(
        connection: Connection, group_email: str, error_supplier: Callable[[], Exception]) -> None:
    api_client: APIClient = APIClient.from_connection(connection)
    if not api_client.get_group(group_email):
        raise error_supplier()
