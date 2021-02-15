import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView
from zentral.contrib.osquery.forms import PackForm, PackQueryForm
from zentral.contrib.osquery.models import Pack, PackQuery, Query


logger = logging.getLogger('zentral.contrib.osquery.views.packs')


class PackListView(LoginRequiredMixin, ListView):
    model = Pack

    def get_queryset(self):
        qs = super().get_queryset()
        return qs.order_by("name", "pk")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["pack_count"] = ctx["object_list"].count()
        return ctx


class CreatePackView(LoginRequiredMixin, CreateView):
    model = Pack
    form_class = PackForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class PackView(LoginRequiredMixin, DetailView):
    model = Pack

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
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
        ctx["can_add_pack_query"] = Query.objects.filter(packquery__isnull=True).count() - ctx["pack_query_count"] > 0
        return ctx


class UpdatePackView(LoginRequiredMixin, UpdateView):
    model = Pack
    form_class = PackForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class DeletePackView(LoginRequiredMixin, DeleteView):
    model = Pack
    success_url = reverse_lazy("osquery:packs")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx


class AddPackQueryView(LoginRequiredMixin, CreateView):
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
        ctx["setup"] = True
        ctx["pack"] = self.pack
        return ctx


class UpdatePackQueryView(LoginRequiredMixin, UpdateView):
    model = PackQuery
    form_class = PackQueryForm

    def get_object(self):
        return (
            self.model.objects.select_related("pack", "query")
                              .get(pk=self.kwargs["pq_pk"], pack__pk=self.kwargs["pk"])
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["pack"] = self.object.pack
        return ctx


class DeletePackQueryView(LoginRequiredMixin, DeleteView):
    model = PackQuery

    def get_object(self):
        pack_query = (self.model.objects
                                .select_related("pack", "query")
                                .get(pk=self.kwargs["pq_pk"], pack__pk=self.kwargs["pk"]))
        self.pack = pack_query.pack
        return pack_query

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        return ctx

    def get_success_url(self):
        return "{}#queries".format(self.pack.get_absolute_url())
