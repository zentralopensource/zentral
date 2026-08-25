"""
Many thanks to Pepijn Bruienne for his work on DEPy!!!
https://github.com/bruienne/depy

original copyright:
(c) 2016 The Regents of the University of Michigan
"""
import logging
from itertools import islice

from requests import Session, RequestException
from requests_oauthlib import OAuth1Session

logger = logging.getLogger("zentral.contrib.mdm.dep_client")


class DEPClientError(Exception):
    def __init__(self, *args, **kwargs):
        self.message = args[0]
        self.error_code = kwargs.pop("error_code", None)
        self.status_code = kwargs.pop("status_code", None)
        super().__init__(*args, **kwargs)

    def __str__(self):
        items = [self.message]
        if self.error_code:
            items.append("error code: {}".format(self.error_code))
        if self.status_code:
            items.append("status code: {}".format(self.status_code))
        return ", ".join(items)


class DEPProfileThrottledError(DEPClientError):
    """Apple is throttling the profile assignment of a device.

    Not a failure: the device is still Apple's to assign, and the response says how long to wait.
    """

    def __init__(self, *args, **kwargs):
        self.retry_after_seconds = kwargs.pop("retry_after_seconds", None)
        super().__init__(*args, **kwargs)

    def __str__(self):
        items = [super().__str__()]
        if self.retry_after_seconds:
            items.append("retry after: {}s".format(self.retry_after_seconds))
        return ", ".join(items)


# the values Apple answers for a device in a profile assignment response
PROFILE_ASSIGNMENT_SUCCESS = "SUCCESS"
PROFILE_ASSIGNMENT_THROTTLED = "THROTTLED"


# fallbacks, used when the account detail advertises no limit for the endpoint. The device array
# endpoints have never been seen advertising one, and /devices answers a request carrying 5000
# serial numbers in full, so the batch size is ours: it is the size a batch is applied at, so that
# one failure does not discard the batches that already succeeded.
DEVICE_BATCH_SIZE = 1000
DEFAULT_PAGINATION_LIMIT = 100


def iter_device_chunks(serial_numbers, batch_size=DEVICE_BATCH_SIZE):
    # an iterator, not a slice, so that a caller can stream a queryset instead of loading a whole
    # virtual server's serial numbers into memory
    serial_numbers = iter(serial_numbers)
    while True:
        chunk = list(islice(serial_numbers, batch_size))
        if not chunk:
            break
        yield chunk


class CursorIterator(object):
    def __init__(self, object_iter):
        self.object_iter = object_iter
        self.cursor = None

    def __iter__(self):
        self.cursor = yield from self.object_iter


class DEPClient(object):
    API_URL = "https://mdmenrollment.apple.com/"
    TOKEN_HEADER = "X-ADM-Auth-Session"
    SERVER_PROTOCOL_VERSION = "3"

    def __init__(self, consumer_key, consumer_secret, access_token, access_secret, batch_request_limit=None):
        self.default_session = Session()
        self.default_session.headers.update({
            "X-Server-Protocol-Version": self.SERVER_PROTOCOL_VERSION,
            "Content-Type": "application/json;charset=UTF8"
        })
        self.oauth_session = OAuth1Session(client_key=consumer_key,
                                           client_secret=consumer_secret,
                                           resource_owner_key=access_token,
                                           resource_owner_secret=access_secret,
                                           realm='ADM')
        # None: ask Apple. An explicit value overrides what the account detail advertises.
        self.batch_request_limit = batch_request_limit
        self._account = None
        self._limits = {}

    @classmethod
    def from_dep_token(cls, dep_token, batch_request_limit=None):
        return cls(dep_token.consumer_key, dep_token.get_consumer_secret(),
                   dep_token.access_token, dep_token.get_access_secret(),
                   batch_request_limit=batch_request_limit)

    @classmethod
    def from_dep_virtual_server(cls, dep_virtual_server, batch_request_limit=None):
        token = dep_virtual_server.token
        if not token:
            raise DEPClientError("DEP virtual server has no token")
        elif token.has_expired():
            raise DEPClientError("DEP virtual server token has expired")
        else:
            return cls.from_dep_token(token, batch_request_limit=batch_request_limit)

    @property
    def auth_session_token(self):
        return self.default_session.headers.get(self.TOKEN_HEADER)

    @auth_session_token.setter
    def auth_session_token(self, token):
        if token:
            self.default_session.headers.update({self.TOKEN_HEADER: token})

    def get_auth_session_token(self, renew=False):
        if self.auth_session_token and not renew:
            return
        try:
            response = self.oauth_session.get(self.API_URL + "session")
            response.raise_for_status()
        except RequestException as e:
            error_code = status_code = None
            if e.response is not None:
                status_code = e.response.status_code
                if status_code == 403:
                    # ACCESS_DENIED or T_C_NOT_SIGNED
                    error_code = e.response.text.strip()
            raise DEPClientError("Could not get auth session token",
                                 error_code=error_code, status_code=status_code)
        else:
            self.auth_session_token = response.json()["auth_session_token"]
            # the account detail describes the authenticated session, so it is dropped with the
            # session it came from and read again on the next use. Dropped, not read here: reading
            # it goes through send_request, which asks for a session token.
            self._account = None
            self._limits = {}

    def send_request(self, endpoint, method="GET", json=None, **params):
        self.get_auth_session_token()
        try:
            response = self.default_session.request(method, self.API_URL + endpoint, json=json, params=params)
            response.raise_for_status()
        except RequestException as e:
            error_code = status_code = None
            if e.response is not None:
                status_code = e.response.status_code
                if status_code in [401, 403]:
                    # ask for a new session token and try again
                    self.get_auth_session_token(renew=True)
                    return self.send_request(endpoint, method, json, **params)
                if status_code == 400:
                    error_code = e.response.text.strip()
            raise DEPClientError("Could not perform operation",
                                 error_code=error_code, status_code=status_code)
        else:
            self.auth_session_token = response.headers.get(self.TOKEN_HEADER)
            try:
                return response.json()
            except ValueError:
                return response.content

    @staticmethod
    def prepare_uuid_for_request(uuid):
        return str(uuid).replace("-", "").upper()

    def get_account(self):
        # cached for the lifetime of the auth session, not of the client
        if self._account is None:
            self._account = self.send_request('account')
        return self._account

    def get_uri_limit(self, uri):
        """The maximum Apple advertises for an endpoint, or None when it advertises none.

        The account detail carries a urls array of {uri, http_method, limit} - see the Url and
        Limit objects of the Device Management documentation. Only the paginated endpoints have
        been seen carrying one, but it is asked for every endpoint: an account that advertises
        more, or a future one that does, is then honoured instead of overrun.
        """
        account = self.get_account()
        if not isinstance(account, dict):
            return None
        for url_d in account.get("urls") or []:
            if not isinstance(url_d, dict) or url_d.get("uri") != uri:
                continue
            maximum = (url_d.get("limit") or {}).get("maximum")
            if isinstance(maximum, int) and maximum > 0:
                return maximum
        return None

    def _get_limit(self, uri, default):
        if uri not in self._limits:
            limit = None
            try:
                limit = self.get_uri_limit(uri)
            except DEPClientError:
                # the account detail is a convenience here, not a precondition: a smaller request
                # costs more of them, it does not make the response wrong
                logger.warning("Could not read the account detail to size the %s requests", uri)
            self._limits[uri] = limit
        return self._limits[uri] or default

    def get_pagination_limit(self, path):
        if self.batch_request_limit is not None:
            return self.batch_request_limit
        return self._get_limit(f"/{path}", DEFAULT_PAGINATION_LIMIT)

    def get_device_batch_size(self, uri):
        """How many devices to send at once: Apple's number when it has already given one.

        This does not read the account detail on its own. No endpoint taking a device array has
        been seen advertising a limit, so fetching it here would add a request to every single
        device operation - a disown, a refresh - to learn nothing. The callers that batch a large
        set read it first, and then an advertised limit is honoured rather than overrun.
        """
        if self._account is None:
            return DEVICE_BATCH_SIZE
        return self._get_limit(uri, DEVICE_BATCH_SIZE)

    def _device_iterator_request(self, path, cursor=None):
        limit = self.get_pagination_limit(path)
        while True:
            body = {"limit": limit}
            if cursor:
                body["cursor"] = cursor
            response = self.send_request(path, 'POST', json=body)
            yield from response.get("devices", [])
            more_to_follow = response.get("more_to_follow", False)
            cursor = response.get("cursor")
            if not more_to_follow:
                return cursor

    def fetch_devices(self):
        return CursorIterator(self._device_iterator_request("server/devices"))

    def sync_devices(self, cursor):
        return CursorIterator(self._device_iterator_request("devices/sync", cursor))

    def get_devices(self, serial_numbers):
        devices_d = {}
        for chunk in iter_device_chunks(serial_numbers, self.get_device_batch_size("/devices")):
            response = self.send_request('devices', 'POST', json={"devices": chunk})
            for serial_number, device_d in response["devices"].items():
                response_status = device_d.pop("response_status")
                if response_status == "SUCCESS":
                    devices_d[serial_number] = device_d
        return devices_d

    def get_profile(self, profile_uuid):
        profile_uuid = self.prepare_uuid_for_request(profile_uuid)
        return self.send_request('profile', profile_uuid=profile_uuid)

    def add_profile(self, profile):
        return self.send_request('profile', 'POST', json=profile)

    def assign_profile(self, profile_uuid, serial_numbers):
        profile_uuid = self.prepare_uuid_for_request(profile_uuid)
        devices = {}
        retry_after_seconds = None
        for chunk in iter_device_chunks(serial_numbers, self.get_device_batch_size("/profile/devices")):
            body = {"devices": chunk, "profile_uuid": profile_uuid}
            response = self.send_request('profile/devices', 'POST', json=body)
            devices.update(response.get("devices") or {})
            # one delay per response, and the longest of them covers the throttled devices of all
            chunk_retry_after_seconds = response.get("retry_after_seconds")
            if isinstance(chunk_retry_after_seconds, int) and chunk_retry_after_seconds > 0:
                if retry_after_seconds is None or chunk_retry_after_seconds > retry_after_seconds:
                    retry_after_seconds = chunk_retry_after_seconds
        result = {"devices": devices}
        if retry_after_seconds is not None:
            result["retry_after_seconds"] = retry_after_seconds
        return result

    def disown_devices(self, serial_numbers):
        devices = {}
        for chunk in iter_device_chunks(serial_numbers, self.get_device_batch_size("/devices/disown")):
            response = self.send_request('devices/disown', 'POST', json={"devices": chunk})
            devices.update(response.get("devices") or {})
        return {"devices": devices}

    def get_os_beta_enrollment_tokens(self):
        return self.send_request('os-beta-enrollment/tokens')
