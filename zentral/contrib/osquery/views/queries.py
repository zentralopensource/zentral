import logging
from urllib.parse import urlencode
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db import models
from django.db.models import Case, Q, Sum, Value, When
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView
from zentral.contrib.osquery.forms import QueryForm, QuerySearchForm
from zentral.contrib.osquery.models import PackQuery, Query
from zentral.core.stores.conf import stores
from zentral.core.stores.views import EventsView, FetchEventsView, EventsStoreRedirectView
from zentral.utils.text import encode_args


logger = logging.getLogger('zentral.contrib.osquery.views.queries')


class QueryListView(PermissionRequiredMixin, ListView):
    permission_required = "osquery.view_query"
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


class CreateQueryView(PermissionRequiredMixin, CreateView):
    permission_required = "osquery.add_query"
    model = Query
    form_class = QueryForm


class QueryView(PermissionRequiredMixin, DetailView):
    permission_required = "osquery.view_query"

    def get_queryset(self):
        return Query.objects.select_related("compliance_check").prefetch_related("packquery__pack")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        try:
            ctx["pack_query"] = self.object.packquery
        except PackQuery.DoesNotExist:
            ctx["pack_query"] = None

        # events
        if self.request.user.has_perm(EventsMixin.permission_required):
            ctx["events_url"] = reverse("osquery:query_events", args=(self.object.pk,))
            store_links = []
            for store in stores.iter_events_url_store_for_user("object", self.request.user):
                url = "{}?{}".format(
                    reverse("osquery:query_events_store_redirect", args=(self.object.pk,)),
                    urlencode({"es": store.name,
                               "tr": EventsView.default_time_range})
                )
                store_links.append((url, store.name))
            ctx["store_links"] = store_links

        # distributed queries
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


class UpdateQueryView(PermissionRequiredMixin, UpdateView):
    permission_required = "osquery.change_query"
    model = Query
    form_class = QueryForm


class DeleteQueryView(PermissionRequiredMixin, DeleteView):
    permission_required = "osquery.delete_query"
    model = Query
    success_url = reverse_lazy("osquery:queries")


class EventsMixin:
    permission_required = "osquery.view_query"
    store_method_scope = "object"

    def get_object(self, **kwargs):
        return get_object_or_404(Query, pk=kwargs["pk"])

    def get_fetch_kwargs_extra(self):
        return {"key": "osquery_query", "val": encode_args((self.object.pk,))}

    def get_fetch_url(self):
        return reverse("osquery:fetch_query_events", args=(self.object.pk,))

    def get_redirect_url(self):
        return reverse("osquery:query_events", args=(self.object.pk,))

    def get_store_redirect_url(self):
        return reverse("osquery:query_events_store_redirect", args=(self.object.pk,))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["query"] = self.object
        return ctx


class QueryEventsView(EventsMixin, EventsView):
    template_name = "osquery/query_events.html"


class FetchQueryEventsView(EventsMixin, FetchEventsView):
    pass


class QueryEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    pass
