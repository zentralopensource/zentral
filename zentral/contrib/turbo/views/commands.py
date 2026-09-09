from django.contrib.auth.mixins import PermissionRequiredMixin
from django.views.generic import DetailView
from ..forms import CommandSearchForm
from ..models import Command
from .base import JobDetailMixin, SearchFormListView


# read-only in the console, like the other two BackendInstance consumers (stores.Store and
# probes.Action): a command is defined through the API, where the per-backend kwargs serializer already
# validates it. The detail page exists because onetimejob_list.html links every definition's
# get_absolute_url, and because it is where the schedules running a command are listed.


class CommandListView(SearchFormListView):
    permission_required = "turbo.view_command"
    model = Command
    search_form_class = CommandSearchForm


class CommandView(PermissionRequiredMixin, JobDetailMixin, DetailView):
    permission_required = "turbo.view_command"

    def get_queryset(self):
        return Command.objects.select_related("job")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        backend = self.object.get_backend(load=True)
        # rendered as a table of key/value pairs rather than per-backend markup: the kwargs are a small
        # options dict by definition, and the shape is the backend's business
        ctx["backend_kwargs"] = sorted(self.object.get_backend_kwargs_for_event().items())
        ctx["artifacts"] = backend.artifacts
        return ctx
