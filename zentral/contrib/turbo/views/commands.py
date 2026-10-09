from django.contrib.auth.mixins import PermissionRequiredMixin
from django.views.generic import DetailView
from ..forms import CommandSearchForm
from ..models import Command
from .base import JobDetailMixin, SearchFormListView


# Read-only in the console, like stores.Store and probes.Action, the other two BackendInstance
# models. An operator defines a command through the API, where the kwargs serializer of the backend
# validates it. The detail page exists for two reasons: onetimejob_list.html links the
# get_absolute_url of every definition, and the page lists the schedules that run the command.


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
        # A table of key/value pairs, not markup for each backend. The kwargs are a small
        # options dict, and the backend owns their shape.
        ctx["backend_kwargs"] = sorted(self.object.get_backend_kwargs_for_event().items())
        ctx["artifacts"] = backend.artifacts
        return ctx
