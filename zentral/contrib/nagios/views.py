import logging
import os.path
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.views.generic import View, ListView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from zentral.conf import settings
from zentral.utils.api_views import APIAuthError, JSONPostAPIView
from .events import post_nagios_event
from .forms import NagiosInstanceForm
from .models import NagiosInstance

logger = logging.getLogger('zentral.contrib.nagios.views')


# setup > nagios instances


class NagiosInstancesView(LoginRequiredMixin, ListView):
    model = NagiosInstance

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        nagios_instances_count = len(ctx["object_list"])
        if nagios_instances_count == 0 or nagios_instances_count > 1:
            suffix = "s"
        else:
            suffix = ""
        ctx["title"] = "{} nagios instance{}".format(nagios_instances_count, suffix)
        return ctx


class CreateNagiosInstanceView(LoginRequiredMixin, CreateView):
    model = NagiosInstance
    form_class = NagiosInstanceForm
    success_url = reverse_lazy("nagios:nagios_instances")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Create nagios instance"
        return ctx


class DownloadNagiosInstanceEventHandlerView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        nagios_instance = get_object_or_404(NagiosInstance, pk=kwargs["pk"])
        base_dir = os.path.dirname(os.path.abspath(__file__))
        event_handler = os.path.join(base_dir, "event_handlers", "zentral_event_handlers_py27.py")
        with open(event_handler, "r") as script_src_f:
            script_src = script_src_f.read()
        script_src = script_src.replace("%SECRET%", nagios_instance.secret)
        script_src = script_src.replace("%TLS_HOSTNAME%", settings["api"]["tls_hostname"])
        fullchain = ""
        if settings['api'].get("distribute_tls_server_certs", True):
            fullchain = settings["api"]["tls_fullchain"]
        script_src = script_src.replace("%FULLCHAIN%", fullchain)
        response = HttpResponse(script_src, content_type="text/x-python")
        response['Content-Disposition'] = 'attachment; filename="{}"'.format(os.path.basename(script_src_f.name))
        return response


class UpdateNagiosInstanceView(LoginRequiredMixin, UpdateView):
    model = NagiosInstance
    form_class = NagiosInstanceForm
    success_url = reverse_lazy("nagios:nagios_instances")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Update nagios instance"
        return ctx


class DeleteNagiosInstanceView(LoginRequiredMixin, DeleteView):
    model = NagiosInstance
    success_url = reverse_lazy("nagios:nagios_instances")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Delete nagios instance"
        return ctx


# API


class PostEventView(JSONPostAPIView):
    def check_request_secret(self, request, *args, **kwargs):
        secret = request.META.get("HTTP_ZENTRAL_API_SECRET", None)
        if not secret:
            raise APIAuthError
        try:
            self.nagios_instance = NagiosInstance.objects.select_related("business_unit").get(secret=secret)
        except NagiosInstance.DoesNotExist:
            raise APIAuthError

    def do_post(self, data):
        post_nagios_event(self.nagios_instance, self.user_agent, self.ip, data)
        return {}
