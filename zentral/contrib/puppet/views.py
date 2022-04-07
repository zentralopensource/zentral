import json
import logging
from urllib.parse import urlencode
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import (HttpResponse,
                         HttpResponseBadRequest, HttpResponseForbidden, HttpResponseNotFound,
                         HttpResponseRedirect)
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.views.generic import DetailView, ListView, TemplateView, View
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from zentral.core.stores import frontend_store, stores
from zentral.core.stores.views import EventsView, FetchEventsView, EventsStoreRedirectView
from zentral.utils.http import user_agent_and_ip_address_from_request
from zentral.utils.text import encode_args
from .events import (post_instance_created_event,
                     post_instance_deleted_event,
                     post_instance_updated_event,
                     post_puppet_report)
from .forms import InstanceForm
from .models import Instance, test_report_processor_token


logger = logging.getLogger('zentral.contrib.puppet.views')


# index


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "puppet/index.html"

    def get_context_data(self, **kwargs):
        if not self.request.user.has_module_perms("puppet"):
            raise PermissionDenied("Not allowed")
        ctx = super().get_context_data(**kwargs)
        instance_qs = Instance.objects.all()
        ctx["instances"] = instance_qs
        ctx["instance_count"] = instance_qs.count()
        return ctx


# instances


class InstanceListView(PermissionRequiredMixin, ListView):
    permission_required = "puppet.view_instance"
    model = Instance


class CreateInstanceView(PermissionRequiredMixin, CreateView):
    permission_required = "puppet.add_instance"
    model = Instance
    form_class = InstanceForm

    def form_valid(self, form):
        response = super().form_valid(form)
        transaction.on_commit(lambda: post_instance_created_event(self.object, self.request))
        return response


class InstanceView(PermissionRequiredMixin, DetailView):
    permission_required = "puppet.view_instance"
    model = Instance

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        if self.request.user.has_perms(EventsMixin.permission_required):
            ctx["show_events_link"] = frontend_store.object_events
            store_links = []
            for store in stores.iter_events_url_store_for_user("object", self.request.user):
                url = "{}?{}".format(
                    reverse("puppet:instance_events_store_redirect", args=(self.object.pk,)),
                    urlencode({"es": store.name,
                               "tr": InstanceEventsView.default_time_range})
                )
                store_links.append((url, store.name))
            ctx["store_links"] = store_links
        return ctx


class UpdateInstanceView(PermissionRequiredMixin, UpdateView):
    permission_required = "puppet.change_instance"
    model = Instance
    form_class = InstanceForm

    def form_valid(self, form):
        response = super().form_valid(form)
        transaction.on_commit(lambda: post_instance_updated_event(self.object, self.request))
        return response


class DeleteInstanceView(PermissionRequiredMixin, DeleteView):
    permission_required = "puppet.delete_instance"
    model = Instance
    success_url = reverse_lazy("puppet:instances")

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        serialized_instance = self.object.serialize_for_event()
        success_url = self.get_success_url()
        self.object.delete()
        transaction.on_commit(lambda: post_instance_deleted_event(serialized_instance, self.request))
        return HttpResponseRedirect(success_url)


class EventsMixin:
    permission_required = ("puppet.view_instance",)
    store_method_scope = "object"

    def get_object(self, **kwargs):
        return get_object_or_404(Instance, pk=kwargs["pk"])

    def get_fetch_kwargs_extra(self):
        return {"key": "puppet_instance", "val": encode_args((self.object.pk,))}

    def get_fetch_url(self):
        return reverse("puppet:fetch_instance_events", args=(self.object.pk,))

    def get_redirect_url(self):
        return reverse("puppet:instance_events", args=(self.object.pk,))

    def get_store_redirect_url(self):
        return reverse("puppet:instance_events_store_redirect", args=(self.object.pk,))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["instance"] = self.object
        return ctx


class InstanceEventsView(EventsMixin, EventsView):
    template_name = "puppet/instance_events.html"


class FetchInstanceEventsView(EventsMixin, FetchEventsView):
    pass


class InstanceEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    pass


# API


class PostReportView(View):
    def post(self, request, *args, **kwargs):
        # header
        auth_header = self.request.META.get("HTTP_AUTHORIZATION", None)
        if not auth_header:
            msg = "Missing Authorization header"
            logger.error(msg, extra={'request': self.request})
            return HttpResponseForbidden(msg)
        try:
            scheme, token = auth_header.split()
            assert scheme.lower() == "token"
        except Exception:
            msg = "Invalid Authorization header"
            logger.error(msg, extra={'request': self.request})
            return HttpResponseForbidden(msg)

        pk = kwargs["pk"]
        try:
            version, observer_dict = test_report_processor_token(pk, token)
        except Instance.DoesNotExist:
            return HttpResponseNotFound("Puppet instance not found")
        except ValueError:
            return HttpResponseForbidden("Invalid token")

        try:
            report = json.load(request)
        except Exception:
            return HttpResponseBadRequest("Could not parse report")

        # trim the report
        report.pop("logs", None)
        report.pop("metrics", None)
        report.pop("resource_statuses", None)

        user_agent, ip = user_agent_and_ip_address_from_request(request)
        post_puppet_report(pk, version, observer_dict, user_agent, ip, report)
        return HttpResponse("OK")
