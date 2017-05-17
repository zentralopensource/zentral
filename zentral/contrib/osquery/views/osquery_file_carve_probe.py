import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views import View
from django.views.generic import ListView
from django.views.generic.edit import FormView
from zentral.core.probes.models import ProbeSource
from zentral.contrib.osquery.forms import CreateFileCarveProbeForm, FileCarveForm
from zentral.contrib.osquery.models import CarveSession

logger = logging.getLogger('zentral.contrib.osquery.views.osquery_file_carve_probe')


class CreateFileCarveProbeView(LoginRequiredMixin, FormView):
    form_class = CreateFileCarveProbeForm
    template_name = "core/probes/form.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Create osquery file carve probe"
        ctx["probes"] = True
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return HttpResponseRedirect(probe_source.get_absolute_url())


class UpdateFileCarveProbePathView(LoginRequiredMixin, FormView):
    form_class = FileCarveForm
    template_name = "osquery/file_carve_path_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        return {'path': self.probe.path}

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['cancel_url'] = self.probe_source.get_absolute_url("osquery")
        return ctx

    def form_valid(self, form):
        body = form.get_body()

        def func(probe_d):
            probe_d.update(body)
        self.probe_source.update_body(func)
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_absolute_url("osquery")


class DownloadFileCarveSessionArchiveView(LoginRequiredMixin, View):
    def dispatch(self, request, *args, **kwargs):
        self.carve_session = get_object_or_404(CarveSession, pk=kwargs["session_id"], archive__isnull=False)
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        response = HttpResponse(self.carve_session.archive, content_type='application/x-tar')
        response['Content-Disposition'] = 'attachment; filename={}'.format(self.carve_session.get_archive_name())
        return response


class FileCarveProbeSessionsView(LoginRequiredMixin, ListView):
    template_name = "osquery/file_carve_probe_sessions.html"
    paginate_by = 25

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"], model="OsqueryFileCarveProbe")
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        return CarveSession.objects.filter(probe_source=self.probe_source).order_by("id")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx["probe_source"] = self.probe_source
        # pagination
        page = ctx["page_obj"]
        if page.has_next():
            qd = self.request.GET.copy()
            qd["page"] = page.next_page_number()
            ctx["next_url"] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd["page"] = page.previous_page_number()
            ctx["previous_url"] = "?{}".format(qd.urlencode())
        # breadcrumbs
        qd = self.request.GET.copy()
        qd.pop('page', None)
        if page.number != 1:
            reset_link = "?{}".format(qd.urlencode())
        else:
            reset_link = None
        ctx["breadcrumbs"] = [(reset_link, "sessions"),
                              (None, "page {} of {}".format(page.number, page.paginator.num_pages))]
        return ctx
