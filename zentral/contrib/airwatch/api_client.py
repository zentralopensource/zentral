import logging
import requests
from requests.packages.urllib3.util import Retry

logger = logging.getLogger('zentral.contrib.airwatch.api_client')


class APIClientError(Exception):
    def __init__(self, message, status_code=None):
        self.message = message
        self.status_code = status_code


class APIClient(object):
    def __init__(self, host, port, path, user, password, aw_tenant_code, business_unit=None, **kwargs):
        self.host, self.path, self.port, self.aw_tenant_code, self.business_unit = host, path, port, aw_tenant_code, business_unit
        self.base_url = "https://{}:{}".format(host, port)
        self.api_base_url = "{}{}".format(self.base_url, path)
        # requests session setup
        self.session = requests.Session()
        self.session.headers.update({'user-agent': 'zentral/0.0.1', 'aw-tenant-code' : self.aw_tenant_code,
                                     'accept': 'application/json'})
        self.session.auth = (user, password)
        max_retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount(self.api_base_url,
                           requests.adapters.HTTPAdapter(max_retries=max_retries))

    def _make_get_query(self, path):
        url = "{}{}".format(self.api_base_url, path)

        try:
            r = self.session.get(url)
        except requests.exceptions.RequestException as e:
            status_code = None
            if e.response is not None:
                status_code = e.response.status_code
            raise APIClientError("Airwatch API error: {}".format(str(e)), status_code)
        if r.status_code != requests.codes.ok:
            raise APIClientError("{} Airwatch API HTTP response status code {}".format(url, r.status_code),
                                 r.status_code)
        return r.json()

    def get_account(self):
        return self._make_get_query("/system/info")

    def upload_app(self, app_filename, app_content, organizationgroupid):
        url = "{}{}?filename={}&organizationgroupid={}&moduleType=Application".format(self.api_base_url,
                                                                                      "/mam/blobs/uploadblob", app_filename, organizationgroupid)
        files = {"binary": (app_filename, app_content)}
        try:
            r = self.session.post(url, files=files)
        except requests.exceptions.RequestException:
            raise APIClientError
        return r.json()["uuid"]

    def delete_app(self, app_id):
        url = "{}{}/{}".format(self.api_base_url, "/apps", app_id)
        try:
            r = self.session.delete(url)
        except requests.exceptions.RequestException:
            raise APIClientError
        return r.status_code == 204
