import logging
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.views.generic import DetailView, View, ListView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from zentral.utils.api_views import APIAuthError, JSONPostAPIView
from .api_client import APIClient, APIClientError
from .events import post_jamf_webhook_event
from .forms import JamfInstanceForm, TagConfigForm
from .models import JamfInstance, TagConfig


logger = logging.getLogger('zentral.contrib.jamf.views')


# setup > jamf instances


class JamfInstancesView(LoginRequiredMixin, ListView):
    model = JamfInstance

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        jamf_instances_count = len(ctx["object_list"])
        if jamf_instances_count == 0 or jamf_instances_count > 1:
            suffix = "s"
        else:
            suffix = ""
        ctx["title"] = "{} jamf instance{}".format(jamf_instances_count, suffix)
        return ctx


class CreateJamfInstanceView(LoginRequiredMixin, CreateView):
    model = JamfInstance
    form_class = JamfInstanceForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Create jamf instance"
        return ctx


class JamfInstanceView(LoginRequiredMixin, DetailView):
    model = JamfInstance

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = str(ctx["object"])
        ctx["tag_configs"] = list(ctx["object"].tagconfig_set.select_related("taxonomy").all())
        ctx["tag_config_count"] = len(ctx["tag_configs"])
        return ctx


class SetupJamfInstanceView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        jamf_instance = get_object_or_404(JamfInstance, pk=kwargs["pk"])
        api_client = APIClient(**jamf_instance.serialize())
        jamf_instance_base_url = jamf_instance.base_url()
        try:
            setup_msg = api_client.setup()
        except APIClientError:
            msg = "Could not setup webhooks on {}.".format(jamf_instance_base_url)
            messages.warning(request, msg)
            logger.exception(msg)
        else:
            msg = "{}: {}".format(jamf_instance_base_url, setup_msg)
            messages.info(request, msg)
            logger.info(msg)
        return redirect(jamf_instance)


class UpdateJamfInstanceView(LoginRequiredMixin, UpdateView):
    model = JamfInstance
    form_class = JamfInstanceForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Update jamf instance"
        return ctx


class DeleteJamfInstanceView(LoginRequiredMixin, DeleteView):
    model = JamfInstance
    success_url = reverse_lazy("jamf:jamf_instances")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Delete jamf instance"
        return ctx

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        jamf_instance_base_url = self.object.base_url()
        api_client = APIClient(**self.object.serialize())
        try:
            api_client.cleanup()
        except APIClientError:
            msg = "Could not remove webhooks configuration on {}.".format(jamf_instance_base_url)
            messages.warning(request, msg)
            logger.exception(msg)
        else:
            msg = "Removed webhooks configuration on {}.".format(jamf_instance_base_url)
            messages.info(request, msg)
            logger.info(msg)
        return response


class CreateTagConfigView(LoginRequiredMixin, CreateView):
    model = TagConfig
    form_class = TagConfigForm

    def dispatch(self, request, *args, **kwargs):
        self.jamf_instance = get_object_or_404(JamfInstance, pk=kwargs.get("pk"))
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Create tag config"
        ctx["jamf_instance"] = self.jamf_instance
        return ctx

    def form_valid(self, form):
        tc = form.save(commit=False)
        tc.instance = self.jamf_instance
        tc.save()
        return redirect(tc)


class UpdateTagConfigView(LoginRequiredMixin, UpdateView):
    model = TagConfig
    form_class = TagConfigForm

    def dispatch(self, request, *args, **kwargs):
        self.jamf_instance = get_object_or_404(JamfInstance, pk=kwargs.get("ji_pk"))
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Update tag config"
        ctx["jamf_instance"] = self.jamf_instance
        return ctx

    def form_valid(self, form):
        tc = form.save(commit=False)
        tc.instance = self.jamf_instance
        tc.save()
        return redirect(tc)


class DeleteTagConfigView(LoginRequiredMixin, DeleteView):
    model = TagConfig

    def dispatch(self, request, *args, **kwargs):
        self.jamf_instance = get_object_or_404(JamfInstance, pk=kwargs.get("ji_pk"))
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Delete tag config"
        ctx["jamf_instance"] = self.jamf_instance
        return ctx

    def get_success_url(self):
        return self.jamf_instance.get_absolute_url()


# API


class PostEventView(JSONPostAPIView):
    payload_encoding = "latin-1"

    def check_request_secret(self, request, *args, **kwargs):
        try:
            self.jamf_instance = JamfInstance.objects.select_related("business_unit").get(secret=kwargs["secret"])
        except JamfInstance.DoesNotExist:
            raise APIAuthError

    def do_post(self, data):
        post_jamf_webhook_event(self.jamf_instance, self.user_agent, self.ip, data)
        return {}
