import logging
from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.views.generic import View
from zentral.conf import settings
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.utils.api_views import BaseEnrollmentView, make_secret, SignedRequestJSONPostAPIView
from .events import post_jss_event

logger = logging.getLogger('zentral.contrib.jss.views')


class EnrollmentView(BaseEnrollmentView):
    template_name = "jss/enrollment.html"
    section = "jss"


class EnrollmentDebuggingView(View):
    debugging_template = """webhook_url=%(tls_hostname)s%(path)s"""

    def get(self, request, *args, **kwargs):
        try:
            mbu = MetaBusinessUnit.objects.get(pk=int(request.GET['mbu_id']))
            # TODO Race. The meta_business_unit could maybe be without any api BU.
            # TODO. Better selection if multiple BU ?
            bu = mbu.api_enrollment_business_units()[0]
        except ValueError:
            bu = None
        debugging_tools = self.debugging_template % {
            'path': reverse("jss:post_event",
                            args=(make_secret("zentral.contrib.jss", bu),)),
            'tls_hostname': settings['api']['tls_hostname']
        }
        return HttpResponse(debugging_tools)


class PostEventView(SignedRequestJSONPostAPIView):
    payload_encoding = "latin-1"
    verify_module = "zentral.contrib.jss"
    tmp_dir = "/tmp/jss_events/"

    def get_request_secret(self, request, *args, **kwargs):
        return kwargs["api_secret"]

    def do_post(self, data):
        post_jss_event(self.user_agent, self.ip, data)
        return {}
