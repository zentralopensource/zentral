from itertools import chain
import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView
from zentral.contrib.osquery.forms import DistributedQueryForm
from zentral.contrib.osquery.models import (DistributedQuery, DistributedQueryMachine, DistributedQueryResult,
                                            FileCarvingSession, Query)


logger = logging.getLogger('zentral.contrib.osquery.views.distributed_queries')


class DistributedQueryListView(LoginRequiredMixin, ListView):
    model = DistributedQuery

    def get_queryset(self):
        return (
            super().get_queryset()
                   .select_related("query")
                   .annotate(machine_count=Count("distributedquerymachine"))
                   .annotate(result_count=Count("distributedqueryresult"))
                   .annotate(file_carving_session_count=Count("filecarvingsession"))
                   .order_by("-created_at", "-pk")
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["distributed_query_count"] = ctx["object_list"].count()
        return ctx


class CreateDistributedQueryView(LoginRequiredMixin, CreateView):
    model = DistributedQuery
    form_class = DistributedQueryForm

    def dispatch(self, request, *args, **kwargs):
        self.query = get_object_or_404(Query, pk=int(request.GET["q"]))
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["query"] = self.query
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["query"] = self.query
        return ctx


class DistributedQueryView(LoginRequiredMixin, DetailView):
    model = DistributedQuery

    def get_queryset(self):
        return super().get_queryset().select_related("query")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["query"] = self.object.query
        ctx["dqm_count"] = self.object.distributedquerymachine_set.count()
        ctx["result_count"] = self.object.distributedqueryresult_set.count()
        ctx["file_carving_session_count"] = self.object.filecarvingsession_set.count()
        return ctx


class UpdateDistributedQueryView(LoginRequiredMixin, UpdateView):
    model = DistributedQuery
    form_class = DistributedQueryForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["query"] = self.object.query
        return ctx


class DeleteDistributedQueryView(LoginRequiredMixin, DeleteView):
    model = DistributedQuery
    success_url = reverse_lazy("osquery:distributed_queries")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["machine_count"] = self.object.distributedquerymachine_set.count()
        ctx["result_count"] = self.object.distributedqueryresult_set.count()
        ctx["file_carving_session_count"] = self.object.filecarvingsession_set.count()
        return ctx


class DistributedQueryMachineListView(LoginRequiredMixin, ListView):
    model = DistributedQueryMachine
    paginate_by = 50

    def get_queryset(self):
        self.distributed_query = get_object_or_404(
            DistributedQuery.objects.select_related("query"), pk=self.kwargs["pk"]
        )
        return (
            super().get_queryset()
                   .filter(distributed_query=self.distributed_query)
                   .order_by("-updated_at", "-created_at", "-pk")
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["distributed_query"] = self.distributed_query
        page = ctx["page_obj"]
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop('page', None)
            ctx['reset_link'] = "?{}".format(qd.urlencode())
        return ctx


class DistributedQueryResultListView(LoginRequiredMixin, ListView):
    model = DistributedQueryResult
    paginate_by = 50

    def get_queryset(self):
        self.distributed_query = get_object_or_404(
            DistributedQuery.objects.select_related("query"), pk=self.kwargs["pk"]
        )
        return (
            super().get_queryset()
                   .filter(distributed_query=self.distributed_query)
                   .order_by("-pk")
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["distributed_query"] = self.distributed_query
        page = ctx["page_obj"]
        ctx["columns"] = sorted(set(chain.from_iterable(r.row.keys() for r in page)))
        ctx["rows"] = [[r.serial_number] + [r.row.get(c) for c in ctx["columns"]] for r in page]
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop('page', None)
            ctx['reset_link'] = "?{}".format(qd.urlencode())
        return ctx


class DistributedQueryFileCarvingSessionListView(LoginRequiredMixin, ListView):
    model = FileCarvingSession
    template_name = "osquery/dq_filecarvingsession_list.html"
    paginate_by = 50

    def get_queryset(self):
        self.distributed_query = get_object_or_404(
            DistributedQuery.objects.select_related("query"), pk=self.kwargs["pk"]
        )
        return (
            super().get_queryset()
                   .filter(distributed_query=self.distributed_query)
                   .annotate(block_seen=Count("filecarvingblock"))
                   .order_by("-created_at", "-pk")
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["distributed_query"] = self.distributed_query
        page = ctx["page_obj"]
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            ctx['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            ctx['previous_url'] = "?{}".format(qd.urlencode())
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop('page', None)
            ctx['reset_link'] = "?{}".format(qd.urlencode())
        return ctx
