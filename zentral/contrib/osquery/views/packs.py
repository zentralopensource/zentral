from datetime import datetime
import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db.models import Count
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView
from zentral.contrib.osquery.forms import PackForm, PackQueryForm
from zentral.contrib.osquery.models import Pack, PackQuery, Query


logger = logging.getLogger('zentral.contrib.osquery.views.packs')


class PackListView(PermissionRequiredMixin, ListView):
    permission_required = "osquery.view_pack"
    model = Pack

    def get_queryset(self):
        qs = super().get_queryset()
        return qs.order_by("name", "pk")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["pack_count"] = ctx["object_list"].count()
        return ctx


class CreatePackView(PermissionRequiredMixin, CreateView):
    permission_required = "osquery.add_pack"
    model = Pack
    form_class = PackForm


class PackView(PermissionRequiredMixin, DetailView):
    permission_required = "osquery.view_pack"
    model = Pack

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration_packs"] = (
            self.object.configurationpack_set.select_related("configuration")
                                             .prefetch_related("tags__taxonomy",
                                                               "tags__meta_business_unit")
                                             .order_by("configuration__name", "pk")
        )
        ctx["configuration_pack_count"] = ctx["configuration_packs"].count()
        ctx["pack_queries"] = (
            self.object.packquery_set.select_related("query")
                                     .annotate(filecarvingsession_count=Count("filecarvingsession"))
                                     .order_by("query__name", "slug", "pk")
        )
        ctx["pack_query_count"] = ctx["pack_queries"].count()
        ctx["can_add_pack_query"] = (
            self.request.user.has_perm("osquery.add_packquery")
            and Query.objects.filter(packquery__isnull=True).count() > 0
        )
        return ctx


class UpdatePackView(PermissionRequiredMixin, UpdateView):
    permission_required = "osquery.change_pack"
    model = Pack
    form_class = PackForm


class DeletePackView(PermissionRequiredMixin, DeleteView):
    permission_required = "osquery.delete_pack"
    model = Pack
    success_url = reverse_lazy("osquery:packs")


class AddPackQueryView(PermissionRequiredMixin, CreateView):
    permission_required = "osquery.add_packquery"
    model = PackQuery
    form_class = PackQueryForm

    def dispatch(self, request, *args, **kwargs):
        self.pack = get_object_or_404(Pack, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["pack"] = self.pack
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["pack"] = self.pack
        return ctx

    def form_valid(self, form):
        response = super().form_valid(form)
        self.object.pack.updated_at = datetime.utcnow()
        self.object.pack.save()
        return response


class UpdatePackQueryView(PermissionRequiredMixin, UpdateView):
    permission_required = "osquery.change_packquery"
    model = PackQuery
    form_class = PackQueryForm

    def get_object(self):
        return (
            self.model.objects.select_related("pack", "query")
                              .get(pk=self.kwargs["pq_pk"], pack__pk=self.kwargs["pk"])
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["pack"] = self.object.pack
        return ctx

    def form_valid(self, form):
        response = super().form_valid(form)
        self.object.pack.updated_at = datetime.utcnow()
        self.object.pack.save()
        return response


class DeletePackQueryView(PermissionRequiredMixin, DeleteView):
    permission_required = "osquery.delete_packquery"
    model = PackQuery

    def get_object(self):
        pack_query = (self.model.objects
                                .select_related("pack", "query")
                                .get(pk=self.kwargs["pq_pk"], pack__pk=self.kwargs["pk"]))
        self.pack = pack_query.pack
        return pack_query

    def get_success_url(self):
        return "{}#queries".format(self.pack.get_absolute_url())
