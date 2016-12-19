import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect
from django.views.generic.edit import FormView
from zentral.core.probes.views import AddProbeItemView, UpdateProbeItemView, DeleteProbeItemView
from zentral.contrib.osquery.forms import CreateFIMProbeForm, FilePathForm

logger = logging.getLogger('zentral.contrib.osquery.views.osquery_fim_probe')


class CreateFIMProbeView(LoginRequiredMixin, FormView):
    form_class = CreateFIMProbeForm
    template_name = "core/probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Create osquery FIM probe"
        ctx["probes"] = True
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return HttpResponseRedirect(probe_source.get_absolute_url())


# file_paths


class AddFIMProbeFilePathView(AddProbeItemView):
    form_class = FilePathForm
    probe_item_attribute = "file_paths"
    template_name = "osquery/file_path_form.html"
    success_anchor = "osquery_fim"


class UpdateFIMProbeFilePathView(UpdateProbeItemView):
    form_class = FilePathForm
    probe_item_attribute = "file_paths"
    template_name = "osquery/file_path_form.html"
    success_anchor = "osquery_fim"
    item_pk_kwarg = "file_path_id"


class DeleteFIMProbeFilePathView(DeleteProbeItemView):
    probe_item_attribute = "file_paths"
    template_name = "osquery/delete_file_path.html"
    success_anchor = "osquery_fim"
    item_pk_kwarg = "file_path_id"
    permission = "can_delete_file_paths"
