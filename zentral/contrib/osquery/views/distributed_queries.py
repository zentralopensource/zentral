from itertools import chain
import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db.models import Count
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView
from zentral.contrib.osquery.forms import DistributedQueryForm
from zentral.contrib.osquery.models import (DistributedQuery, DistributedQueryMachine, DistributedQueryResult,
                                            FileCarvingSession, Query)


logger = logging.getLogger('zentral.contrib.osquery.views.distributed_queries')


class DistributedQueryListView(PermissionRequiredMixin, ListView):
    permission_required = "osquery.view_distributedquery"
    model = DistributedQuery
    paginate_by = 50

    def get_queryset(self):
        return (
            super().get_queryset()
                   .select_related("query")
                   .annotate(machine_count=Count("distributedquerymachine", distinct=True))
                   .annotate(result_count=Count("distributedqueryresult", distinct=True))
                   .annotate(file_carving_session_count=Count("filecarvingsession", distinct=True))
                   .order_by("-created_at", "-pk")
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        page = ctx["page_obj"]
        ctx["distributed_query_count"] = page.paginator.count
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


class CreateDistributedQueryView(PermissionRequiredMixin, CreateView):
    permission_required = "osquery.add_distributedquery"
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
        ctx["query"] = self.query
        return ctx


class DistributedQueryView(PermissionRequiredMixin, DetailView):
    permission_required = "osquery.view_distributedquery"
    model = DistributedQuery

    def get_queryset(self):
        return super().get_queryset().select_related("query")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["query"] = self.object.query
        ctx["dqm_count"] = self.object.distributedquerymachine_set.count()
        ctx["result_count"] = self.object.distributedqueryresult_set.count()
        ctx["file_carving_session_count"] = self.object.filecarvingsession_set.count()
        return ctx


class UpdateDistributedQueryView(PermissionRequiredMixin, UpdateView):
    permission_required = "osquery.change_distributedquery"
    model = DistributedQuery
    form_class = DistributedQueryForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["query"] = self.object.query
        return ctx


class DeleteDistributedQueryView(PermissionRequiredMixin, DeleteView):
    permission_required = "osquery.delete_distributedquery"
    model = DistributedQuery
    success_url = reverse_lazy("osquery:distributed_queries")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["machine_count"] = self.object.distributedquerymachine_set.count()
        ctx["result_count"] = self.object.distributedqueryresult_set.count()
        ctx["file_carving_session_count"] = self.object.filecarvingsession_set.count()
        return ctx


class DistributedQueryMachineListView(PermissionRequiredMixin, ListView):
    permission_required = "osquery.view_distributedquery"
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


class DistributedQueryResultListView(PermissionRequiredMixin, ListView):
    permission_required = "osquery.view_distributedquery"
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
        ctx["distributed_query"] = self.distributed_query
        page = ctx["page_obj"]
        fields = set(chain.from_iterable(r.row.keys() for r in page))
        selected_fields = set(self.request.GET.getlist("f")).intersection(fields)
        for field in sorted(fields):
            qd = self.request.GET.copy()
            qdf = qd.setlistdefault("f", [])
            if field in selected_fields:
                ctx_key = "selected_fields"
                while True:
                    try:
                        qdf.pop(qdf.index(field))
                    except ValueError:
                        break
            else:
                ctx_key = "available_fields"
                qdf.append(field)
            ctx.setdefault(ctx_key, []).append(
                ("{}?{}".format(self.request.path, qd.urlencode()), field)
            )
        rows = []
        selected_fields = sorted(selected_fields)
        if selected_fields:
            for result in page:
                rows.append((result.serial_number, [result.row.get(field) for field in selected_fields]))
        ctx["rows"] = rows
        ctx["headers"] = ["Serial number"] + selected_fields
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


class DistributedQueryFileCarvingSessionListView(PermissionRequiredMixin, ListView):
    permission_required = ("osquery.view_distributedquery", "osquery.view_filecarvingsession")
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
