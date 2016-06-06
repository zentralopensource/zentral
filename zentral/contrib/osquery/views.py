import json
import logging
from dateutil import parser
from django.core.urlresolvers import reverse, reverse_lazy
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.generic import View, DetailView, ListView, TemplateView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from zentral.conf import settings
from zentral.contrib.inventory.models import MachineSnapshot, MetaBusinessUnit, MetaMachine
from zentral.core.probes.conf import ProbeList
from zentral.utils.api_views import (JSONPostAPIView, make_secret, verify_secret, APIAuthError,
                                     BaseEnrollmentView, BaseInstallerPackageView)
from .conf import build_osquery_conf, DEFAULT_ZENTRAL_INVENTORY_QUERY
from .events import post_enrollment_event, post_request_event, post_events_from_osquery_log
from .forms import DistributedQueryForm, DistributedQuerySearchForm
from .models import enroll, DistributedQuery, DistributedQueryNode
from .osx_package.builder import OsqueryZentralEnrollPkgBuilder
from .probes import OSQueryProbe

logger = logging.getLogger('zentral.contrib.osquery.views')


class ProbesView(TemplateView):
    template_name = "osquery/probes.html"

    def get_context_data(self, **kwargs):
        context = super(ProbesView, self).get_context_data(**kwargs)
        context['osquery'] = True
        pl = ProbeList()  # not all_probes to avoid cache inconsistency
        context['probes'] = pl.class_filter(OSQueryProbe)
        context['event_type_probes'] = pl.module_prefix_filter("osquery").exclude_class(OSQueryProbe)
        return context


class EnrollmentView(BaseEnrollmentView):
    template_name = "osquery/enrollment.html"
    section = "osquery"


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


class DistributedIndexView(ListView):
    model = DistributedQuery
    paginate_by = 10

    def get(self, request, *args, **kwargs):
        self.search_form = DistributedQuerySearchForm(request.GET)
        return super(DistributedIndexView, self).get(request, *args, **kwargs)

    def get_queryset(self, **kwargs):
        qs = DistributedQuery.objects.all()
        if self.search_form.is_valid():
            mbu = self.search_form.cleaned_data['meta_business_unit']
            if mbu:
                qs = qs.filter(meta_business_unit=mbu)
            tag = self.search_form.cleaned_data['tag']
            if tag:
                qs = qs.filter(tags=tag)
        return qs

    def get_context_data(self, **kwargs):
        ctx = super(DistributedIndexView, self).get_context_data(**kwargs)
        ctx['osquery'] = True
        ctx['search_form'] = self.search_form
        # pagination
        page = ctx['page_obj']
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        # breadcrumbs
        l = []
        qd = self.request.GET.copy()
        qd.pop('page', None)
        reset_link = "?{}".format(qd.urlencode())
        if self.search_form.is_valid() and len([i for i in self.search_form.cleaned_data.values() if i]):
            l.append((reverse('osquery:distributed_index'), 'Osquery distributed queries'))
            l.append((reset_link, "Search"))
        else:
            l.append((reset_link, "Osquery distributed queries"))
        l.append((None, "page {} of {}".format(page.number, page.paginator.num_pages)))
        ctx['breadcrumbs'] = l
        return ctx


class CreateDistributedView(CreateView):
    model = DistributedQuery
    form_class = DistributedQueryForm

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
    form_class = DistributedQueryForm

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
            for dqn in DistributedQueryNode.objects.new_queries_for_machine(machine):
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
                    'reference': self.ms.reference}
            if self.business_unit:
                tree['business_unit'] = self.business_unit.serialize()
            for t in last_snapshot:
                table_name = t.pop('table_name')
                if table_name == 'os_version':
                    tree['os_version'] = t
                elif table_name == 'system_info':
                    tree['system_info'] = t
            try:
                MachineSnapshot.objects.commit(tree)
            except:
                logger.exception('Cannot save machine snapshot')
        post_events_from_osquery_log(self.machine_serial_number,
                                     self.user_agent, self.ip, data)
        return {}
