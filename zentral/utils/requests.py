import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util import Retry
from base.utils import deployment_info


class CustomHTTPAdapter(HTTPAdapter):
    def __init__(self, default_timeout, retries, raise_on_status=True, respect_retry_after_header=True):
        self.default_timeout = default_timeout
        super().__init__(
            max_retries=Retry(
                total=retries,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                raise_on_status=raise_on_status,
                respect_retry_after_header=respect_retry_after_header,
            )
        )

    def send(self, *args, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.default_timeout
        return super().send(*args, **kwargs)


def make_session(timeout=10, max_retries=1):
    session = requests.Session()
    session.headers["User-Agent"] = deployment_info.user_agent
    # the callers check the status of the last response, and urllib3 does not cap a Retry-After wait
    adapter = CustomHTTPAdapter(timeout, max_retries, raise_on_status=False, respect_retry_after_header=False)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session
