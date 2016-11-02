import json
import logging
from dateutil import parser
from django.core.urlresolvers import reverse
from django.http import Http404, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.generic import View, TemplateView
from django.views.generic.edit import FormView
from zentral.conf import settings
from zentral.contrib.inventory.models import MachineSnapshot, MetaBusinessUnit, MetaMachine
from zentral.core.probes.models import ProbeSource
from zentral.utils.api_views import (JSONPostAPIView, make_secret, verify_secret, APIAuthError,
                                     BaseEnrollmentView, BaseInstallerPackageView)
from .conf import build_osquery_conf, DEFAULT_ZENTRAL_INVENTORY_QUERY
from .events import (post_distributed_query_result, post_enrollment_event,
                     post_events_from_osquery_log, post_request_event)
from .forms import (CreateProbeForm, CreateComplianceProbeForm, CreateDistributedQueryProbeForm, CreateFIMProbeForm,
                    QueryForm, PreferenceFileForm, KeyFormSet, FileChecksumForm, DistributedQueryForm, FilePathForm)
from .models import enroll, DistributedQueryProbeMachine
from .osx_package.builder import OsqueryZentralEnrollPkgBuilder
from .deb_script.builder import OsqueryZentralEnrollScriptBuilder

logger = logging.getLogger('zentral.contrib.osquery.views')


class EnrollmentView(BaseEnrollmentView):
    template_name = "osquery/enrollment.html"


class EnrollmentDebuggingView(View):
    debugging_template = """machine_serial_number="0123456789"
enroll_secret="%(secret)s\$SERIAL\$$machine_serial_number"
node_key_json=$(curl -XPOST -k -d '{"enroll_secret":"'"$enroll_secret"'"}' %(tls_hostname)s%(enroll_path)s)
echo $node_key_json | jq .
curl -XPOST -k -d "$node_key_json"  %(tls_hostname)s%(config_path)s | jq ."""

    def get(self, request, *args, **kwargs):
        try:
            mbu = MetaBusinessUnit.objects.get(pk=int(request.GET['mbu_id']))
            # -> BaseInstallerPackageView
            # TODO Race. The meta_business_unit could maybe be without any api BU.
            # TODO. Better selection if multiple BU ?
            bu = mbu.api_enrollment_business_units()[0]
        except ValueError:
            bu = None
        debugging_tools = self.debugging_template % {'config_path': reverse("osquery:config"),
                                                     'enroll_path': reverse("osquery:enroll"),
                                                     'secret': make_secret("zentral.contrib.osquery", bu),
                                                     'tls_hostname': settings['api']['tls_hostname']}
        return HttpResponse(debugging_tools)


class InstallerPackageView(BaseInstallerPackageView):
    builder = OsqueryZentralEnrollPkgBuilder
    module = "zentral.contrib.osquery"


class SetupScriptView(BaseInstallerPackageView):
    builder = OsqueryZentralEnrollScriptBuilder
    module = "zentral.contrib.osquery"


# query probes


class CreateProbeView(FormView):
    form_class = CreateProbeForm
    template_name = "osquery/create_probe.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Create osquery probe"
        ctx["probes"] = True
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return HttpResponseRedirect(probe_source.get_absolute_url())


class AddProbeQueryView(FormView):
    form_class = QueryForm
    template_name = "osquery/query_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['add_query'] = True
        ctx['cancel_url'] = self.probe_source.get_absolute_url("osquery")
        return ctx

    def form_valid(self, form):
        query_d = form.get_query_d()

        def func(probe_d):
            queries = probe_d.setdefault("queries", [])
            queries.append(query_d)
        self.probe_source.update_body(func)
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_absolute_url("osquery")


class UpdateProbeQueryView(FormView):
    form_class = QueryForm
    template_name = "osquery/query_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        self.query_id = int(kwargs["query_id"])
        try:
            self.query = self.probe.queries[self.query_id]
        except IndexError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        return self.form_class.get_initial(self.query)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['add_query'] = False
        ctx['cancel_url'] = self.probe_source.get_absolute_url("osquery")
        return ctx

    def form_valid(self, form):
        query_d = form.get_query_d()

        def func(probe_d):
            probe_d["queries"][self.query_id] = query_d
        self.probe_source.update_body(func)
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_absolute_url("osquery")


class DeleteProbeQueryView(TemplateView):
    template_name = "osquery/delete_query.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        self.query_id = int(kwargs["query_id"])
        try:
            self.query_d = self.probe.queries[self.query_id]
        except IndexError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['add_query'] = False
        ctx['cancel_url'] = self.probe_source.get_absolute_url("osquery")
        return ctx

    def post(self, request, *args, **kwargs):
        if self.probe.can_delete_queries:
            def func(probe_d):
                probe_d["queries"].pop(self.query_id)
                if not probe_d["queries"]:
                    probe_d.pop("queries")
            self.probe_source.update_body(func)
        return HttpResponseRedirect(self.probe_source.get_absolute_url("osquery"))


# compliance probes


class CreateComplianceProbeView(FormView):
    form_class = CreateComplianceProbeForm
    template_name = "osquery/create_compliance_probe.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['title'] = 'Create osquery compliance probe'
        ctx['probes'] = True
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return HttpResponseRedirect(probe_source.get_absolute_url())


class AddComplianceProbePreferenceFileView(TemplateView):
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
        preference_file = self.preference_file_form.cleaned_data
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


class UpdateComplianceProbePreferenceFileView(TemplateView):
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
        preference_file = self.preference_file_form.cleaned_data
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


class DeleteComplianceProbePreferenceFileView(TemplateView):
    template_name = "osquery/delete_preference_file.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        self.preference_file_id = int(kwargs["pf_id"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['cancel_url'] = self.probe_source.get_absolute_url("osquery_compliance")
        return ctx

    def post(self, request, *args, **kwargs):
        if self.probe.can_delete_items:
            def func(probe_d):
                probe_d['preference_files'].pop(self.preference_file_id)
                if not probe_d['preference_files']:
                    probe_d.pop('preference_files')
            self.probe_source.update_body(func)
        return HttpResponseRedirect(self.probe_source.get_absolute_url("osquery_compliance"))


class AddComplianceProbeFileChecksumView(FormView):
    form_class = FileChecksumForm
    template_name = "osquery/file_checksum_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['add_checksum'] = True
        ctx['cancel_url'] = self.probe_source.get_absolute_url("osquery_compliance")
        return ctx

    def form_valid(self, form):
        file_checksum = form.cleaned_data

        def func(probe_d):
            file_checksums = probe_d.setdefault('file_checksums', [])
            file_checksums.append(file_checksum)
        self.probe_source.update_body(func)
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_absolute_url("file_checksums")


class UpdateComplianceProbeFileChecksumView(FormView):
    form_class = FileChecksumForm
    template_name = "osquery/file_checksum_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        self.file_checksum_id = int(kwargs["fc_id"])
        try:
            self.file_checksum = self.probe.file_checksums[self.file_checksum_id]
        except IndexError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        return self.form_class.get_initial(self.file_checksum)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['add_checksum'] = False
        ctx['cancel_url'] = self.probe_source.get_absolute_url("file_checksums")
        return ctx

    def form_valid(self, form):
        file_checksum = form.cleaned_data

        def func(probe_d):
            probe_d["file_checksums"][self.file_checksum_id] = file_checksum
        self.probe_source.update_body(func)
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_absolute_url("file_checksums")


class DeleteComplianceProbeFileChecksumView(TemplateView):
    template_name = "osquery/delete_file_checksum.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        self.file_checksum_id = int(kwargs["fc_id"])
        try:
            self.file_checksum = self.probe.file_checksums[self.file_checksum_id]
        except IndexError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['cancel_url'] = self.probe_source.get_absolute_url("file_checksums")
        return ctx

    def post(self, request, *args, **kwargs):
        if self.probe.can_delete_items:
            def func(probe_d):
                probe_d["file_checksums"].pop(self.file_checksum_id)
                if not probe_d["file_checksums"]:
                    probe_d.pop("file_checksums")
            self.probe_source.update_body(func)
        return HttpResponseRedirect(self.probe_source.get_absolute_url("osquery_compliance"))


# distributed query probes


class CreateDistributedQueryProbeView(FormView):
    form_class = CreateDistributedQueryProbeForm
    template_name = "osquery/create_probe.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Create osquery distributed query probe"
        ctx["probes"] = True
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return HttpResponseRedirect(probe_source.get_absolute_url())


class DownloadDistributedView(View):
    def get(self, request, *args, **kwargs):
        probe_source = get_object_or_404(ProbeSource, pk=kwargs['probe_id'])
        probe = probe_source.load()
        return JsonResponse(probe.serialize())


class UpdateDistributedQueryProbeQueryView(FormView):
    form_class = DistributedQueryForm
    template_name = "osquery/distributed_query_query_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        return {'query': self.probe.distributed_query}

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


# FIM probes


class CreateFIMProbeView(FormView):
    form_class = CreateFIMProbeForm
    template_name = "osquery/create_fim_probe.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Create osquery FIM probe"
        ctx["probes"] = True
        return ctx

    def form_valid(self, form):
        probe_source = form.save()
        return HttpResponseRedirect(probe_source.get_absolute_url())


class AddFIMProbeFilePathView(FormView):
    form_class = FilePathForm
    template_name = "osquery/file_path_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['add_file_path'] = True
        ctx['cancel_url'] = self.probe_source.get_absolute_url("osquery_fim")
        return ctx

    def form_valid(self, form):
        file_path = form.get_file_path()

        def func(probe_d):
            file_paths = probe_d.setdefault("file_paths", [])
            file_paths.append(file_path)
        self.probe_source.update_body(func)
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_absolute_url("osquery_fim")


class UpdateFIMProbeFilePathView(FormView):
    form_class = FilePathForm
    template_name = "osquery/file_path_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        self.file_path_id = int(kwargs["file_path_id"])
        try:
            self.file_path = self.probe.file_paths[self.file_path_id]
        except IndexError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        return self.form_class.get_file_path_initial(self.file_path)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['add_file_path'] = False
        ctx['cancel_url'] = self.probe_source.get_absolute_url("osquery_fim")
        return ctx

    def form_valid(self, form):
        file_path = form.get_file_path()

        def func(probe_d):
            probe_d["file_paths"][self.file_path_id] = file_path
        self.probe_source.update_body(func)
        return super().form_valid(form)

    def get_success_url(self):
        return self.probe_source.get_absolute_url("osquery_fim")


class DeleteFIMProbeFilePathView(TemplateView):
    template_name = "osquery/delete_file_path.html"

    def dispatch(self, request, *args, **kwargs):
        self.probe_source = get_object_or_404(ProbeSource, pk=kwargs["probe_id"])
        self.probe = self.probe_source.load()
        self.file_path_id = int(kwargs["file_path_id"])
        try:
            self.file_path = self.probe.file_paths[self.file_path_id]
        except IndexError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["probes"] = True
        ctx['probe_source'] = self.probe_source
        ctx['probe'] = self.probe
        ctx['cancel_url'] = self.probe_source.get_absolute_url("osquery_fim")
        return ctx

    def post(self, request, *args, **kwargs):
        if self.probe.can_delete_file_paths:
            def func(probe_d):
                probe_d["osquery_fim"].pop(self.file_path_id)
                if not probe_d["osquery_fim"]:
                    probe_d.pop("osquery_fim")
            self.probe_source.update_body(func)
        return HttpResponseRedirect(self.probe_source.get_absolute_url("osquery_fim"))


# API


class EnrollView(JSONPostAPIView):
    def check_data_secret(self, data):
        data = verify_secret(data['enroll_secret'], "zentral.contrib.osquery")
        self.machine_serial_number = data['machine_serial_number']
        self.business_unit = data.get('business_unit', None)

    def do_post(self, data):
        ms, action = enroll(self.machine_serial_number,
                            self.business_unit)
        post_enrollment_event(ms.machine.serial_number,
                              self.user_agent, self.ip,
                              {'action': action})
        return {'node_key': ms.reference}


class BaseNodeView(JSONPostAPIView):
    def check_data_secret(self, data):
        auth_err = None
        try:
            self.ms = MachineSnapshot.objects.current().get(source__module='zentral.contrib.osquery',
                                                            reference=data['node_key'])
        except KeyError:
            auth_err = "Missing node_key"
        except MachineSnapshot.DoesNotExist:
            auth_err = "Wrong node_key"
        if auth_err:
            logger.error("APIAuthError %s", auth_err, extra=data)
            raise APIAuthError(auth_err)
        # TODO: Better verification ?
        self.machine_serial_number = self.ms.machine.serial_number
        self.business_unit = self.ms.business_unit

    def do_post(self, data):
        post_request_event(self.machine_serial_number,
                           self.user_agent, self.ip,
                           self.request_type)
        return self.do_node_post(data)


class ConfigView(BaseNodeView):
    request_type = "config"

    def do_node_post(self, data):
        # TODO: The machine serial number is included in the string used to authenticate the requests
        # This is done in the osx pkg builder. The machine serial number should always be present here.
        # Maybe we could code a fallback to the available mbu probes if the serial number is not present.
        return build_osquery_conf(MetaMachine(self.machine_serial_number))


class DistributedReadView(BaseNodeView):
    request_type = "distributed_read"

    def do_node_post(self, data):
        queries = {}
        if self.machine_serial_number:
            machine = MetaMachine(self.machine_serial_number)
            queries = DistributedQueryProbeMachine.objects.new_queries_for_machine(machine)
        return {'queries': queries}


class DistributedWriteView(BaseNodeView):
    request_type = "distributed_write"

    def do_node_post(self, data):
        payloads = []

        def get_probe_pk(key):
            return int(key.split('_')[-1])

        queries = data['queries']
        ps_d = {ps.id: ps
                for ps in ProbeSource.objects.filter(
                    model='OsqueryDistributedQueryProbe',
                    pk__in=[get_probe_pk(k) for k in queries.keys()]
                )}
        for key, val in queries.items():
            try:
                probe_source = ps_d[get_probe_pk(key)]
            except KeyError:
                logger.error("Unknown distributed query probe %s", key)
            else:
                payload = {'probe': {'id': probe_source.pk,
                                     'name': probe_source.name}}
                try:
                    status = int(data['statuses'][key])
                except KeyError:
                    # osquery < 2.1.2 has no statuses
                    status = 0
                if status > 0:
                    # error
                    payload["error"] = True
                elif status == 0:
                    payload["error"] = False
                    if val:
                        payload["result"] = val
                    else:
                        payload["empty"] = True
                else:
                    raise ValueError("Unknown distributed query status '{}'".format(status))
                payloads.append(payload)
        post_distributed_query_result(self.machine_serial_number,
                                      self.user_agent, self.ip,
                                      payloads)
        return {}


class LogView(BaseNodeView):
    request_type = "log"

    def do_node_post(self, data):
        inventory_results = []
        other_results = []
        data_data = data.pop('data')
        if not isinstance(data_data, list):
            # TODO verify. New since osquery 1.6.4 ?
            data_data = [json.loads(data_data)]
        for r in data_data:
            if r.get('name', None) == DEFAULT_ZENTRAL_INVENTORY_QUERY:
                inventory_results.append((parser.parse(r['calendarTime']), r['snapshot']))
            else:
                other_results.append(r)
        data['data'] = other_results
        if inventory_results:
            inventory_results.sort(reverse=True)
            last_snapshot = inventory_results[0][1]
            tree = {'source': {'module': self.ms.source.module,
                               'name': self.ms.source.name},
                    'machine': {'serial_number': self.machine_serial_number},
                    'reference': self.ms.reference,
                    'public_ip_address': self.ip}
            if self.business_unit:
                tree['business_unit'] = self.business_unit.serialize()
            for t in last_snapshot:
                table_name = t.pop('table_name')
                if table_name == 'os_version':
                    tree['os_version'] = t
                elif table_name == 'system_info':
                    tree['system_info'] = t
                elif table_name == 'network_interface':
                    tree.setdefault('network_interfaces', []).append(t)
            try:
                MachineSnapshot.objects.commit(tree)
            except:
                logger.exception('Cannot save machine snapshot')
        post_events_from_osquery_log(self.machine_serial_number,
                                     self.user_agent, self.ip, data)
        return {}
