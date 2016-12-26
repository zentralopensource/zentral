import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views.generic import TemplateView
from django.views.generic.edit import FormView
from zentral.core.probes.models import ProbeSource
from zentral.core.probes.views import AddProbeItemView, UpdateProbeItemView, DeleteProbeItemView
from zentral.contrib.osquery.forms import CreateComplianceProbeForm, PreferenceFileForm, KeyFormSet, FileChecksumForm

logger = logging.getLogger('zentral.contrib.osquery.views.osquery_compliance_probe')


class CreateComplianceProbeView(LoginRequiredMixin, FormView):
    form_class = CreateComplianceProbeForm
    template_name = "core/probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['title'] = 'Create osquery compliance probe'
        ctx['probes'] = True
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return HttpResponseRedirect(probe_source.get_absolute_url())


# preference_files


class AddComplianceProbePreferenceFileView(LoginRequiredMixin, TemplateView):
    template_name = "osquery/preference_file_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['title'] = 'Add compliance probe preference file'
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['cancel_url'] = self.probe_source.get_absolute_url("osquery_compliance")
        ctx['preference_file_form'] = self.preference_file_form
        ctx['key_form_set'] = self.key_form_set
        return ctx

    def forms_valid(self):
        preference_file = self.preference_file_form.get_item_d()
        preference_file['keys'] = self.key_form_set.get_keys()

        def func(probe_d):
            preference_files = probe_d.setdefault("preference_files", [])
            preference_files.append(preference_file)
        self.probe_source.update_body(func)
        return HttpResponseRedirect(self.probe_source.get_absolute_url("preference_files"))

    def get(self, request, *args, **kwargs):
        self.preference_file_form = PreferenceFileForm(prefix='pff')
        self.key_form_set = KeyFormSet(prefix='kfs')
        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        self.preference_file_form = PreferenceFileForm(request.POST, prefix='pff')
        self.key_form_set = KeyFormSet(request.POST, prefix='kfs')
        if self.preference_file_form.is_valid() and self.key_form_set.is_valid():
            return self.forms_valid()
        else:
            return self.render_to_response(self.get_context_data())


class UpdateComplianceProbePreferenceFileView(LoginRequiredMixin, TemplateView):
    template_name = "osquery/preference_file_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        self.preference_file_id = int(kwargs["pf_id"])
        try:
            self.preference_file = self.probe.preference_files[self.preference_file_id]
        except IndexError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['title'] = 'Update compliance probe preference file'
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['cancel_url'] = self.probe_source.get_absolute_url("osquery_compliance")
        ctx['preference_file_form'] = self.preference_file_form
        ctx['key_form_set'] = self.key_form_set
        return ctx

    def forms_valid(self):
        preference_file = self.preference_file_form.get_item_d()
        preference_file['keys'] = self.key_form_set.get_keys()

        def func(probe_d):
            probe_d["preference_files"][self.preference_file_id] = preference_file
        self.probe_source.update_body(func)
        return HttpResponseRedirect(self.probe_source.get_absolute_url("preference_files"))

    def get(self, request, *args, **kwargs):
        self.preference_file_form = PreferenceFileForm(prefix='pff',
                                                       initial=PreferenceFileForm.get_initial(self.preference_file))
        self.key_form_set = KeyFormSet(prefix='kfs',
                                       initial=KeyFormSet.get_initial(self.preference_file))
        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        self.preference_file_form = PreferenceFileForm(request.POST, prefix='pff')
        self.key_form_set = KeyFormSet(request.POST, prefix='kfs')
        if self.preference_file_form.is_valid() and self.key_form_set.is_valid():
            return self.forms_valid()
        else:
            return self.render_to_response(self.get_context_data())


class DeleteComplianceProbePreferenceFileView(DeleteProbeItemView):
    probe_item_attribute = "preference_files"
    permission = "can_delete_items"
    item_pk_kwarg = "pf_id"
    template_name = "osquery/delete_preference_file.html"
    success_anchor = "osquery_compliance"


# file_checksums


class AddComplianceProbeFileChecksumView(AddProbeItemView):
    form_class = FileChecksumForm
    probe_item_attribute = "file_checksums"
    template_name = "osquery/file_checksum_form.html"
    success_anchor = "file_checksums"


class UpdateComplianceProbeFileChecksumView(UpdateProbeItemView):
    form_class = FileChecksumForm
    probe_item_attribute = "file_checksums"
    item_pk_kwarg = "fc_id"
    template_name = "osquery/file_checksum_form.html"
    success_anchor = "file_checksums"


class DeleteComplianceProbeFileChecksumView(DeleteProbeItemView):
    probe_item_attribute = "file_checksums"
    permission = "can_delete_items"
    item_pk_kwarg = "fc_id"
    template_name = "osquery/delete_file_checksum.html"
    success_anchor = "osquery_compliance"
