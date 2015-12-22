import logging
from django.core.urlresolvers import reverse_lazy
from django.http import JsonResponse, Http404
from django.shortcuts import get_object_or_404
from django.views.generic import View, DetailView, ListView, TemplateView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from zentral.conf import settings
from zentral.contrib.inventory.models import MachineSnapshot
from zentral.core.stores import stores
from zentral.utils.api_views import JSONPostAPIView, verify_secret, APIAuthError, make_secret
from . import osquery_conf, probes
from .events import post_enrollment_event, post_request_event, post_events_from_osquery_log
from .models import enroll, DistributedQuery, DistributedQueryNode
from .osx_package.builder import OsqueryZentralEnrollPkgBuilder

logger = logging.getLogger('zentral.contrib.osquery.views')


class IndexView(TemplateView):
    template_name = "osquery/index.html"

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        context['osquery'] = True
        context['probes'] = probes
        context['last_dq'] = DistributedQuery.objects.all()[:10]
        return context


class InstallerPackageView(View):
    def post(self, request):
        try:
            tls_server_certs = settings['api']['tls_server_certs']
        except KeyError:
            tls_server_certs = None
        builder = OsqueryZentralEnrollPkgBuilder()
        return builder.build_and_make_response(request.get_host(),
                                               make_secret("zentral.contrib.osquery"),
                                               tls_server_certs)


class ProbeView(TemplateView):
    template_name = "osquery/probe.html"

    def get_context_data(self, **kwargs):
        context = super(ProbeView, self).get_context_data(**kwargs)
        context['osquery'] = True

        # find probe
        # TODO log(1)
        probe = None
        for probe_name, probe_d in probes:
            if probe_name == kwargs['probe_key']:
                probe = probe_d
                break
        if not probe:
            raise Http404
        context['probe'] = probe

        # queries
        schedule = []
        file_paths = {}
        for idx, osquery in enumerate(probe['osquery']['schedule']):
            # query links. match query_name.
            query_links = []
            query_name = "{}_{}".format(probe['name'], idx)
            for store in stores:
                url = store.get_visu_url({'name': [query_name]})
                if url:
                    query_links.append((store.name, url))
            query_links.sort()
            schedule.append((osquery, query_links))
        file_paths = probe['osquery'].get('file_paths', {})
        context['osquery_schedule'] = schedule
        context['osquery_file_paths'] = file_paths

        # probe links. query name starts with probe name.
        probe_links = []
        for store in stores:
            url = store.get_visu_url({'name__startswith': [probe['name']]})
            if url:
                probe_links.append((store.name, url))
        probe_links.sort()
        context['probe_links'] = probe_links
        return context


class DistributedIndexView(ListView):
    model = DistributedQuery

    def get_context_data(self, **kwargs):
        ctx = super(DistributedIndexView, self).get_context_data(**kwargs)
        ctx['osquery'] = True
        return ctx


class CreateDistributedView(CreateView):
    model = DistributedQuery
    fields = ['query']

    def get_context_data(self, **kwargs):
        ctx = super(CreateDistributedView, self).get_context_data(**kwargs)
        ctx['osquery'] = True
        return ctx


class DistributedView(DetailView):
    model = DistributedQuery

    def get_context_data(self, **kwargs):
        ctx = super(DistributedView, self).get_context_data(**kwargs)
        ctx['osquery'] = True
        return ctx


class UpdateDistributedView(UpdateView):
    model = DistributedQuery
    fields = ['query']

    def get_context_data(self, **kwargs):
        ctx = super(UpdateDistributedView, self).get_context_data(**kwargs)
        ctx['osquery'] = True
        return ctx


class DeleteDistributedView(DeleteView):
    model = DistributedQuery
    success_url = reverse_lazy('osquery:distributed_index')

    def get_context_data(self, **kwargs):
        ctx = super(DeleteDistributedView, self).get_context_data(**kwargs)
        ctx['osquery'] = True
        return ctx


class DownloadDistributedView(View):
    def get(self, request, *args, **kwargs):
        dq = get_object_or_404(DistributedQuery, pk=kwargs['pk'])
        return JsonResponse(dq.serialize())


# API


class EnrollView(JSONPostAPIView):
    def check_data_secret(self, data):
        data = verify_secret(data['enroll_secret'], "zentral.contrib.osquery")
        self.machine_serial_number = data['machine_serial_number']

    def do_post(self, data):
        ms, action = enroll(self.machine_serial_number)
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

    def do_post(self, data):
        post_request_event(self.machine_serial_number,
                           self.user_agent, self.ip,
                           self.request_type)
        return self.do_node_post(data)


class ConfigView(BaseNodeView):
    request_type = "config"

    def do_node_post(self, data):
        return osquery_conf


class DistributedReadView(BaseNodeView):
    request_type = "distributed_read"

    def do_node_post(self, data):
        queries = {}
        if self.machine_serial_number:
            for dqn in DistributedQueryNode.objects.new_queries_with_serial_number(self.machine_serial_number):
                dq = dqn.distributed_query
                queries['q_{}'.format(dq.id)] = dq.query
        return {'queries': queries}


class DistributedWriteView(BaseNodeView):
    request_type = "distributed_write"

    def do_node_post(self, data):
        for key, val in data.get('queries').items():
            dq_id = int(key.rsplit('_', 1)[-1])
            sn = self.machine_serial_number
            try:
                dqn = DistributedQueryNode.objects.get(distributed_query__id=dq_id,
                                                       machine_serial_number=sn)
            except DistributedQueryNode.DoesNotExist:
                logger.error("Unknown distributed query node query %s sn %s", dq_id, sn)
            else:
                dqn.set_json_result(val)
        return {}


class LogView(BaseNodeView):
    request_type = "log"

    def do_node_post(self, data):
        post_events_from_osquery_log(self.machine_serial_number,
                                     self.user_agent, self.ip, data)
        return {}
