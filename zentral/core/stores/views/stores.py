import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.views.generic import DetailView, ListView
from zentral.core.stores.models import Store


logger = logging.getLogger("zentral.core.stores.views")


class IndexView(PermissionRequiredMixin, ListView):
    permission_required = "stores.view_store"
    model = Store
    template_name = "stores/index.html"

    def get_ordering(self):
        return "name"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["store_count"] = ctx["object_list"].count()
        return ctx


class StoreView(PermissionRequiredMixin, DetailView):
    permission_required = "stores.view_store"
    model = Store
