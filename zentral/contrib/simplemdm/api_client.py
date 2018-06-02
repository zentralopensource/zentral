import logging
import requests
from requests.packages.urllib3.util import Retry


logger = logging.getLogger('zentral.contrib.simplemdm.api_client')


class APIClientError(Exception):
    def __init__(self, message, status_code=None):
        self.message = message
        self.status_code = status_code


class APIClient(object):
    BASE_URL = "https://a.simplemdm.com/api/v1"

    def __init__(self, api_key):
        # requests session setup
        self.session = requests.Session()
        self.session.headers.update({'user-agent': 'zentral/0.0.1',
                                     'accept': 'application/json'})
        self.session.auth = (api_key, "")
        max_retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount(self.BASE_URL,
                           requests.adapters.HTTPAdapter(max_retries=max_retries))

    def _make_get_query(self, path):
        url = "{}{}".format(self.BASE_URL, path)
        try:
            r = self.session.get(url)
        except requests.exceptions.RequestException as e:
            status_code = None
            if e.response is not None:
                status_code = e.response.status_code
            raise APIClientError("SimpleMDM API error: {}".format(str(e)), status_code)
        if r.status_code != requests.codes.ok:
            raise APIClientError("{} SimpleMDM API HTTP response status code {}".format(url, r.status_code),
                                 r.status_code)
        return r.json()

    def get_account(self):
        return self._make_get_query("/account")["data"]["attributes"]

    def upload_app(self, app_filename, app_content):
        url = "{}{}".format(self.BASE_URL, "/apps")
        files = {"binary": (app_filename, app_content)}
        try:
            r = self.session.post(url, files=files)
        except requests.exceptions.RequestException:
            raise APIClientError
        response_data = r.json()
        errors = response_data.get("errors", None)
        error_msg = None
        if errors:
            error_msg = ", ".join(error.get("title", "") for error in errors)
        if error_msg or r.status_code != 201:
            raise APIClientError(error_msg)
        return response_data["data"]

    def delete_app(self, app_id):
        url = "{}{}/{}".format(self.BASE_URL, "/apps", app_id)
        try:
            r = self.session.delete(url)
        except requests.exceptions.RequestException:
            raise APIClientError
        return r.status_code == 204
