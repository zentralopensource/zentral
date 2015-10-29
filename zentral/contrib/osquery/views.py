import json
import logging
from django.core.urlresolvers import reverse_lazy
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.generic import View, DetailView, ListView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from . import osquery_conf
from .events import post_enrollment_event, post_events_from_osquery_log
from .models import Node, EnrollError, DistributedQuery, DistributedQueryNode

logger = logging.getLogger('django_zentral.osquery.views')


class DistributedIndexView(ListView):
    model = DistributedQuery

    def get_context_data(self, **kwargs):
        ctx = super(DistributedIndexView, self).get_context_data(**kwargs)
        ctx['configuration'] = True
        return ctx


class CreateDistributedView(CreateView):
    model = DistributedQuery
    fields = ['query']

    def get_context_data(self, **kwargs):
        ctx = super(CreateDistributedView, self).get_context_data(**kwargs)
        ctx['configuration'] = True
        return ctx


class DistributedView(DetailView):
    model = DistributedQuery

    def get_context_data(self, **kwargs):
        ctx = super(DistributedView, self).get_context_data(**kwargs)
        ctx['configuration'] = True
        return ctx


class UpdateDistributedView(UpdateView):
    model = DistributedQuery
    fields = ['query']

    def get_context_data(self, **kwargs):
        ctx = super(UpdateDistributedView, self).get_context_data(**kwargs)
        ctx['configuration'] = True
        return ctx


class DeleteDistributedView(DeleteView):
    model = DistributedQuery
    success_url = reverse_lazy('osquery:distributed_index')

    def get_context_data(self, **kwargs):
        ctx = super(DeleteDistributedView, self).get_context_data(**kwargs)
        ctx['configuration'] = True
        return ctx


class DownloadDistributedView(View):
    def get(self, request, *args, **kwargs):
        dq = get_object_or_404(DistributedQuery, pk=kwargs['pk'])
        return JsonResponse(dq.serialize())

# API


class BaseView(View):
    def post(self, request):
        data = json.loads(request.body.decode('utf-8'))
        return self.do_post(data)


class EnrollView(BaseView):
    def do_post(self, data):
        try:
            node, action = Node.objects.enroll(data['enroll_secret'])
        except (KeyError, EnrollError):
            logger.exception("Could not enroll node",
                             extra={'request': self.request})
            response_data = {'node_invalid': True}
        else:
            response_data = {'node_key': node.key}
            post_enrollment_event(node.machine_serial_number(),
                                  self.request.META.get("HTTP_USER_AGENT", ""),
                                  self.request.META.get("HTTP_X_REAL_IP", ""),
                                  node.serialize())
        return JsonResponse(response_data)


class BaseNodeView(BaseView):
    def do_post(self, data):
        try:
            node = Node.objects.get(key=data['node_key'])
        except (KeyError, Node.DoesNotExist):
            return JsonResponse({'node_invalid': True})
        else:
            return self.do_post_with_node(node, data)


class ConfigView(BaseNodeView):
    def do_post_with_node(self, node, data):
        return JsonResponse(osquery_conf)


class DistributedReadView(BaseNodeView):
    def do_post_with_node(self, node, data):
        machine_serial_number = node.machine_serial_number()
        queries = {}
        if machine_serial_number:
            for dqn in DistributedQueryNode.objects.new_queries_with_serial_number(machine_serial_number):
                dq = dqn.distributed_query
                queries['q_{}'.format(dq.id)] = dq.query
        return JsonResponse({'queries': queries})


class DistributedWriteView(BaseNodeView):
    def do_post_with_node(self, node, data):
        for key, val in data.get('queries').items():
            dq_id = int(key.rsplit('_', 1)[-1])
            sn = node.machine_serial_number()
            try:
                dqn = DistributedQueryNode.objects.get(distributed_query__id=dq_id,
                                                       machine_serial_number=sn)
            except DistributedQueryNode.DoesNotExist:
                logger.error("Unknown distributed query node query %s sn %s", dq_id, sn)
            else:
                dqn.result = val
                dqn.save()
        return JsonResponse({})


class LogView(BaseNodeView):
    def do_post_with_node(self, node, data):
        user_agent = self.request.META.get("HTTP_USER_AGENT", "")
        ip = self.request.META.get("HTTP_X_REAL_IP", "")
        post_events_from_osquery_log(node.machine_serial_number(),
                                     user_agent, ip, data)
        return JsonResponse({})
