from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util import Retry


class CustomHTTPAdapter(HTTPAdapter):
    def __init__(self, default_timeout, retries):
        self.default_timeout = default_timeout
        super().__init__(
            max_retries=Retry(
                total=retries + 1,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504]
            )
        )

    def send(self, *args, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.default_timeout
        return super().send(*args, **kwargs)
