import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.views.generic import DetailView
from zentral.conf import settings
from zentral.utils.views import UserPaginationListView
from .models import State


logger = logging.getLogger("zentral.core.terraform.views")


class IndexView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "terraform.view_state"
    model = State
    template_name = "terraform/index.html"

    def get_queryset(self):
        return super().get_queryset().select_related("created_by").order_by("slug")


class StateView(PermissionRequiredMixin, DetailView):
    permission_required = "terraform.view_state"
    model = State

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["fqdn"] = settings["api"]["fqdn"]
        if self.request.user.has_perm("terraform.view_stateversion"):
            ctx["state_versions"] = list(self.object.stateversion_set.select_related("created_by").order_by("-pk"))
        return ctx
