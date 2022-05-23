import base64
import logging
from urllib.parse import urlencode
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.crypto import constant_time_compare
from django.views.generic import DetailView, ListView, TemplateView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from zentral.core.stores.conf import frontend_store, stores
from zentral.core.stores.views import EventsView, FetchEventsView, EventsStoreRedirectView
from zentral.utils.api_views import APIAuthError, JSONPostAPIView
from zentral.utils.text import encode_args
from .events import (post_instance_created_event,
                     post_instance_deleted_event,
                     post_instance_updated_event,
                     post_webhook_event)
from .forms import InstanceForm
from .models import Instance


logger = logging.getLogger('zentral.contrib.wsone.views')


# index


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "wsone/index.html"

    def get_context_data(self, **kwargs):
        if not self.request.user.has_module_perms("wsone"):
            raise PermissionDenied("Not allowed")
        ctx = super().get_context_data(**kwargs)
        instance_qs = Instance.objects.all()
        ctx["instances"] = instance_qs
        ctx["instance_count"] = instance_qs.count()
        return ctx


# instances


class InstanceListView(PermissionRequiredMixin, ListView):
    permission_required = "wsone.view_instance"
    model = Instance


class CreateInstanceView(PermissionRequiredMixin, CreateView):
    permission_required = "wsone.add_instance"
    model = Instance
    form_class = InstanceForm

    def form_valid(self, form):
        response = super().form_valid(form)
        transaction.on_commit(lambda: post_instance_created_event(self.object, self.request))
        return response


class InstanceView(PermissionRequiredMixin, DetailView):
    permission_required = "wsone.view_instance"
    model = Instance

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        if self.request.user.has_perm(EventsMixin.permission_required):
            ctx["show_events_link"] = frontend_store.object_events
            store_links = []
            for store in stores.iter_events_url_store_for_user("object", self.request.user):
                url = "{}?{}".format(
                    reverse("wsone:instance_events_store_redirect", args=(self.object.pk,)),
                    urlencode({"es": store.name,
                               "tr": InstanceEventsView.default_time_range})
                )
                store_links.append((url, store.name))
            ctx["store_links"] = store_links
        return ctx


class UpdateInstanceView(PermissionRequiredMixin, UpdateView):
    permission_required = "wsone.change_instance"
    model = Instance
    form_class = InstanceForm

    def form_valid(self, form):
        response = super().form_valid(form)
        transaction.on_commit(lambda: post_instance_updated_event(self.object, self.request))
        return response


class DeleteInstanceView(PermissionRequiredMixin, DeleteView):
    permission_required = "wsone.delete_instance"
    model = Instance
    success_url = reverse_lazy("wsone:instances")

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        serialized_instance = self.object.serialize_for_event()
        success_url = self.get_success_url()
        self.object.delete()
        transaction.on_commit(lambda: post_instance_deleted_event(serialized_instance, self.request))
        return HttpResponseRedirect(success_url)


class EventsMixin:
    permission_required = "wsone.view_instance"
    store_method_scope = "object"

    def get_object(self, **kwargs):
        return get_object_or_404(Instance, pk=kwargs["pk"])

    def get_fetch_kwargs_extra(self):
        return {"key": "wsone_instance", "val": encode_args((self.object.pk,))}

    def get_fetch_url(self):
        return reverse("wsone:fetch_instance_events", args=(self.object.pk,))

    def get_redirect_url(self):
        return reverse("wsone:instance_events", args=(self.object.pk,))

    def get_store_redirect_url(self):
        return reverse("wsone:instance_events_store_redirect", args=(self.object.pk,))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["instance"] = self.object
        return ctx


class InstanceEventsView(EventsMixin, EventsView):
    template_name = "wsone/instance_events.html"


class FetchInstanceEventsView(EventsMixin, FetchEventsView):
    pass


class InstanceEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    pass


# event notifications


class EventNotificationsView(JSONPostAPIView):
    def check_basic_auth(self):
        auth_header = self.request.META.get("HTTP_AUTHORIZATION", None)
        if not auth_header:
            logger.error("Missing Authorization header", extra={'request': self.request})
            raise APIAuthError
        if isinstance(auth_header, str):
            auth_header = auth_header.encode("utf-8")
        try:
            scheme, params = auth_header.split()
            assert scheme.lower() == b"basic"
            decoded_params = base64.b64decode(params)
            username, password = decoded_params.split(b":", 1)
        except Exception:
            logger.error("Invalid basic authentication header", extra={'request': self.request})
            raise APIAuthError
        self.instance = get_object_or_404(Instance, pk=self.kwargs["pk"])
        if (
            constant_time_compare(self.instance.username, username)
            and constant_time_compare(self.instance.get_password(), password)
        ):
            return
        else:
            logger.error("Invalid username or password", extra={'request': self.request})
            raise APIAuthError

    def check_request_secret(self, request, *args, **kwargs):
        self.check_basic_auth()

    def do_post(self, data):
        post_webhook_event(self.instance, self.user_agent, self.ip, data)
        return {}

    def get(self, request, *args, **kwargs):
        self.check_basic_auth()
        logger.info("Workspace ONE instance %s: test event notifications",
                    self.instance.pk, extra={'request': self.request})
        return HttpResponse("OK")
