import json
import logging

from django.contrib.auth.mixins import AccessMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpResponseServerError
from django.views.defaults import server_error as django_server_error
from django.views.generic import CreateView, DeleteView, ListView, UpdateView

from pbac.engine import engine
from zentral.core.events.base import AuditEvent


logger = logging.getLogger("zentral.utils.views")


class UserPaginationMixin:
    def get_paginate_by(self, queryset=None):
        return self.request.user.items_per_page


class UserPaginationListView(UserPaginationMixin, ListView):
    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        page = ctx['page_obj']
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        return ctx


class CreateViewWithAudit(CreateView):
    def on_commit_callback_extra(self):
        pass

    def form_valid(self, form):
        response = super().form_valid(form)

        def on_commit_callback():
            event = AuditEvent.build_from_request_and_instance(
                self.request, self.object,
                action=AuditEvent.Action.CREATED,
            )
            event.post()
            self.on_commit_callback_extra()

        transaction.on_commit(on_commit_callback)
        return response


class UpdateViewWithAudit(UpdateView):
    def on_commit_callback_extra(self):
        pass

    def form_valid(self, form):
        obj = self.get_object()  # self.object is already updated
        prev_value = obj.serialize_for_event()
        response = super().form_valid(form)

        def on_commit_callback():
            event = AuditEvent.build_from_request_and_instance(
                self.request, self.object,
                action=AuditEvent.Action.UPDATED,
                prev_value=prev_value
            )
            event.post()
            self.on_commit_callback_extra()

        transaction.on_commit(on_commit_callback)
        return response


class DeleteViewWithAudit(DeleteView):
    def on_commit_callback_extra(self):
        pass

    def form_valid(self, form):
        # build the event before the object is deleted
        event = AuditEvent.build_from_request_and_instance(
            self.request, self.object,
            action=AuditEvent.Action.DELETED,
            prev_value=self.object.serialize_for_event()
        )

        def on_commit_callback():
            event.post()
            self.on_commit_callback_extra()

        transaction.on_commit(on_commit_callback)
        return super().form_valid(form)


def server_error(request, *args, **kwargs):
    accept = request.headers.get("Accept", "")
    json_content = None
    json_content_type = "application/json"
    if "application/scim+json" in accept:
        json_content_type = "application/scim+json"
        json_content = {
            'detail': 'Internal server error.',
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
            'status': 500
        }
    elif (
        request.path_info.startswith("/api/")
        or "application/json" in accept
    ):
        json_content = {"error": "Server Error (500)"}
    if json_content:
        return HttpResponseServerError(
            json.dumps(json_content),
            content_type=json_content_type
        )
    return django_server_error(request)


class LocalSuperuserRequiredMixin(AccessMixin):
    """Require an authenticated superuser logged in with a local (non-realm)
    session. Used for capabilities that effectively grant root — like editing
    PBAC policies — which must be gated outside the policy system that they
    are meant to bound. Anonymous requests are redirected to login; everything
    else gets 403.
    """

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()
        if not request.user.is_superuser or request.realm_authentication_session.is_remote:
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)


class PBACViewMixin(AccessMixin):
    pbac_request_class = None

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()
        pbac_request = self.pbac_request_class(
            request.user,
            **self.get_pbac_request_kwargs(kwargs),
        )
        engine.authorize_request(pbac_request)
        if not pbac_request.is_authorized:
            logger.error("Permission denied %s", pbac_request, extra={"request": request})
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)
