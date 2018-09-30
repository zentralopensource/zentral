"""
Many thanks to Pepijn Bruienne for his work on DEPy!!!
https://github.com/bruienne/depy

original copyright:
(c) 2016 The Regents of the University of Michigan
"""
from requests import Session, RequestException
from requests_oauthlib import OAuth1Session


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

    def __init__(self, consumer_key, consumer_secret, access_token, access_secret, batch_request_limit=100):
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
        self.batch_request_limit = batch_request_limit

    @classmethod
    def from_dep_token(cls, dep_token, batch_request_limit=100):
        return cls(dep_token.consumer_key, dep_token.consumer_secret,
                   dep_token.access_token, dep_token.access_secret,
                   batch_request_limit=batch_request_limit)

    @classmethod
    def from_dep_virtual_server(cls, dep_virtual_server, batch_request_limit=100):
        token = dep_virtual_server.token
        if not token:
            raise ValueError("DEP virtual server has no token")
        elif token.has_expired():
            raise ValueError("DEP virtual server token has expired")
        else:
            return cls.from_dep_token(token)

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
        return self.send_request('account')

    def _device_iterator_request(self, path, cursor=None):
        while True:
            body = {"limit": self.batch_request_limit}
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
        body = {"devices": serial_numbers}
        response = self.send_request('devices', 'POST', json=body)
        devices_d = {}
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

    def remove_profile(self, serial_numbers):
        body = {"devices": serial_numbers}
        return self.send_request('profile/devices', 'DELETE', json=body)

    def assign_profile(self, profile_uuid, serial_numbers):
        body = {"devices": serial_numbers,
                "profile_uuid": self.prepare_uuid_for_request(profile_uuid)}
        return self.send_request('profile/devices', 'POST', json=body)
