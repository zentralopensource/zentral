import json
import logging
import os
import shlex
from subprocess import check_output
from django.core.urlresolvers import reverse_lazy
from django.http import JsonResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404
from django.views.generic import View, DetailView, ListView, TemplateView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from zentral.contrib.inventory.models import MachineSnapshot
from zentral.core.stores import stores
from . import enroll_secret_secret, osquery_conf, probes
from .events import post_enrollment_event, post_request_event, post_events_from_osquery_log
from .models import EnrollError, enroll, DistributedQuery, DistributedQueryNode

logger = logging.getLogger('zentral.contrib.osquery.views')

PKG_BUILD_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "osx_package/build.sh")


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
        installer_file = check_output([PKG_BUILD_SCRIPT,
                                       shlex.quote(request.get_host()),
                                       shlex.quote(enroll_secret_secret)])
        installer_file = installer_file.strip()
        # TODO: Memory.
        with open(installer_file, 'rb') as f:
            content = f.read()
        response = HttpResponse(content, "application/octet-stream")
        response['Content-Length'] = os.path.getsize(installer_file)
        response['Content-Disposition'] = 'attachment; filename="zentral_osquery_enroll.pkg"'
        os.unlink(installer_file)
        os.rmdir(os.path.dirname(installer_file))
        return response


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


class BaseView(View):
    def dispatch(self, request, *args, **kwargs):
        self.user_agent = request.META.get("HTTP_USER_AGENT", "")
        self.ip = request.META.get("HTTP_X_REAL_IP", "")
        return super(BaseView, self).dispatch(request, *args, **kwargs)

    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        return self.do_post(data)


class EnrollView(BaseView):
    def do_post(self, data):
        try:
            ms, action = enroll(data['enroll_secret'])
        except (KeyError, EnrollError):
            logger.exception("Could not enroll node",
                             extra={'request': self.request})
            response_data = {'node_invalid': True}
        else:
            response_data = {'node_key': ms.reference}
            data = {'action': action,
                    'machine_snapshot': ms.serialize()}
            post_enrollment_event(ms.machine.serial_number,
                                  self.request.META.get("HTTP_USER_AGENT", ""),
                                  self.request.META.get("HTTP_X_REAL_IP", ""),
                                  data)
        return JsonResponse(response_data)


class BaseNodeView(BaseView):
    def do_post(self, data):
        try:
            ms = MachineSnapshot.objects.current().get(source="zentral.contrib.osquery",
                                                       reference=data['node_key'])
        except (KeyError, MachineSnapshot.DoesNotExist):
            return JsonResponse({'node_invalid': True})
        else:
            post_request_event(ms.machine.serial_number,
                               self.user_agent,
                               self.ip,
                               self.request_type)
            return self.do_post_with_ms(ms, data)


class ConfigView(BaseNodeView):
    request_type = "config"

    def do_post_with_ms(self, ms, data):
        return JsonResponse(osquery_conf)


class DistributedReadView(BaseNodeView):
    request_type = "distributed_read"

    def do_post_with_ms(self, ms, data):
        machine_serial_number = ms.machine.serial_number
        queries = {}
        if machine_serial_number:
            for dqn in DistributedQueryNode.objects.new_queries_with_serial_number(machine_serial_number):
                dq = dqn.distributed_query
                queries['q_{}'.format(dq.id)] = dq.query
        return JsonResponse({'queries': queries})


class DistributedWriteView(BaseNodeView):
    request_type = "distributed_write"

    def do_post_with_ms(self, ms, data):
        for key, val in data.get('queries').items():
            dq_id = int(key.rsplit('_', 1)[-1])
            sn = ms.machine.serial_number
            try:
                dqn = DistributedQueryNode.objects.get(distributed_query__id=dq_id,
                                                       machine_serial_number=sn)
            except DistributedQueryNode.DoesNotExist:
                logger.error("Unknown distributed query node query %s sn %s", dq_id, sn)
            else:
                dqn.set_json_result(val)
        return JsonResponse({})


class LogView(BaseNodeView):
    request_type = "log"

    def do_post_with_ms(self, ms, data):
        post_events_from_osquery_log(ms.machine.serial_number,
                                     self.user_agent, self.ip, data)
        return JsonResponse({})
