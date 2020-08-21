from datetime import datetime
import logging
from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpRequest
from django.http.request import split_domain_port
from .http import user_agent_and_ip_address_from_request


class CustomJSONEncoder(DjangoJSONEncoder):
    def prepare_http_request(request):
        return request.META

    def default(self, o):
        try:
            return super().default(o)
        except TypeError:
            return str(o)


class JSONFormatter(logging.Formatter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.json_encoder = CustomJSONEncoder()

    @staticmethod
    def add_request(rd, request):
        rd["request"] = request.META

    @staticmethod
    def add_status_code(rd, status_code):
        rd["status_code"] = status_code

    def format(self, record):
        rd = {"message": record.getMessage(),
              "level":  record.levelname,
              "time": datetime.utcnow()}

        # _info
        if record.exc_info:
            rd["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            rd["stack_info"] = self.formatStack(record.stack_info)

        # request
        request = getattr(record, "request", None)
        if isinstance(request, HttpRequest):
            self.add_request(rd, request)

        # status code
        status_code = getattr(record, "status_code", None)
        if status_code is not None:
            self.add_status_code(rd, status_code)

        try:
            return self.json_encoder.encode(rd)
        except Exception:
            # should not happen
            return '{"message": "Could not encode the log record", "level": "ERROR"}'


class DatadogJSONFormatter(JSONFormatter):
    @staticmethod
    def add_request(rd, request):
        # http, network
        user_agent, ip_address = user_agent_and_ip_address_from_request(request)
        if ip_address:
            rd["network"] = {"client": {"ip": ip_address}}
        domain, port = split_domain_port(request.get_host())
        url_details = {"host": domain,
                       "path": request.path_info,
                       "queryString": request.GET.dict(),
                       "scheme": request.scheme}
        http = rd.setdefault("http", {})
        http.update({"url": request.get_full_path(),
                     "url_details": url_details,
                     "method": request.method})
        referer = request.META.get("HTTP_REFERER")
        if referer:
            http["referer"] = referer
        if user_agent:
            http["useragent"] = user_agent
        if port:
            url_details["port"] = int(port)
        if port:
            http["url_details"]
        rd["http"] = http

        # user
        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            rd["usr"] = {"id": user.pk,
                         "name": user.get_username(),
                         "email": user.email}

    @staticmethod
    def add_status_code(rd, status_code):
        http = rd.setdefault("http", {})
        http["status_code"] = status_code
