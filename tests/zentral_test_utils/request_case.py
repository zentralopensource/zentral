from abc import ABC, abstractmethod


class RequestCase(ABC):

    def __init__(self):
        super().__init__()

    @abstractmethod
    def _getAPIKey(self) -> str:
        pass

    def make_request(self, url, data=None, include_token=True, method="GET"):
        kwargs = {}
        if data is not None:
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self._getAPIKey()}"
        if method == "POST":
            return self.client.post(url, **kwargs)
        else:
            return self.client.get(url, **kwargs)

    def get(self, url, data=None, include_token=True):
        return self.make_request(url, data, include_token, method="GET")

    def post(self, url, data=None, include_token=True):
        return self.make_request(url, data, include_token, method="POST")

    def delete(self, url, include_token=True):
        kwargs = {}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self._getAPIKey()}"
        return self.client.delete(url, **kwargs)

    def post_json_data(self, url, data, include_token=True):
        kwargs = {'content_type': 'application/json',
                  'data': data}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self._getAPIKey()}"
        return self.client.post(url, **kwargs)

    def put_json_data(self, url, data, include_token=True):
        kwargs = {'content_type': 'application/json',
                  'data': data}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self._getAPIKey()}"
        return self.client.put(url, **kwargs)
