import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import models
from django.db.models import Case, Q, Sum, Value, When
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView
from zentral.contrib.osquery.forms import QueryForm, QuerySearchForm
from zentral.contrib.osquery.models import PackQuery, Query


logger = logging.getLogger('zentral.contrib.osquery.views.queries')


class QueryListView(LoginRequiredMixin, ListView):
    paginate_by = 50
    model = Query

    def get(self, request, *args, **kwargs):
        self.form = QuerySearchForm(request.GET)
        self.form.is_valid()
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["form"] = self.form
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


class CreateQueryView(LoginRequiredMixin, CreateView):
    model = Query
    form_class = QueryForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class QueryView(LoginRequiredMixin, DetailView):
    model = Query

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        try:
            ctx["pack_query"] = self.object.packquery
        except PackQuery.DoesNotExist:
            ctx["pack_query"] = None
        match_value = Value(1, output_field=models.IntegerField())
        miss_value = Value(0, output_field=models.IntegerField())
        ctx["distributed_queries"] = (
            self.object.distributedquery_set
            .annotate(in_flight_count=Sum(
                Case(When(Q(distributedquerymachine__serial_number__isnull=False) &
                          Q(distributedquerymachine__status__isnull=True),
                          then=match_value), default=miss_value)
            ))
            .annotate(ok_count=Sum(
                Case(When(distributedquerymachine__status=0, then=match_value), default=miss_value)
            ))
            .annotate(error_count=Sum(
                Case(When(distributedquerymachine__status__gte=1, then=match_value), default=miss_value)
            ))
            .order_by("-pk")
        )
        ctx["distributed_query_count"] = ctx["distributed_queries"].count()
        return ctx


class UpdateQueryView(LoginRequiredMixin, UpdateView):
    model = Query
    form_class = QueryForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class DeleteQueryView(LoginRequiredMixin, DeleteView):
    model = Query
    success_url = reverse_lazy("osquery:queries")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx
