import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db.models import Count
from django.shortcuts import get_object_or_404
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView
from zentral.contrib.osquery.forms import ConfigurationForm, ConfigurationPackForm
from zentral.contrib.osquery.models import Configuration, ConfigurationPack, Pack


logger = logging.getLogger('zentral.contrib.osquery.views.configurations')


class ConfigurationListView(PermissionRequiredMixin, ListView):
    permission_required = "osquery.view_configuration"
    model = Configuration

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration_count"] = ctx["object_list"].count()
        return ctx


class CreateConfigurationView(PermissionRequiredMixin, CreateView):
    permission_required = "osquery.add_configuration"
    model = Configuration
    form_class = ConfigurationForm


class ConfigurationView(PermissionRequiredMixin, DetailView):
    permission_required = "osquery.view_configuration"
    model = Configuration

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["atcs"] = self.object.automatic_table_constructions.all().order_by("name", "pk")
        ctx["atc_count"] = ctx["atcs"].count()
        ctx["file_categories"] = self.object.file_categories.all().order_by("name", "pk")
        ctx["file_category_count"] = ctx["file_categories"].count()
        ctx["enrollments"] = self.object.enrollment_set.select_related("secret").all().order_by("pk")
        ctx["enrollments_count"] = ctx["enrollments"].count()
        ctx["configuration_packs"] = (
            self.object.configurationpack_set
                       .select_related("pack")
                       .prefetch_related("tags__meta_business_unit",
                                         "tags__taxonomy")
                       .annotate(query_count=Count("pack__packquery"))
                       .order_by("pack__name", "pk")
        )
        ctx["configuration_pack_count"] = ctx["configuration_packs"].count()
        ctx["can_add_configuration_pack"] = (
            self.request.user.has_perm("osquery.change_configuration")
            and (Pack.objects.count() - ctx["configuration_pack_count"]) > 0
        )
        return ctx


class UpdateConfigurationView(PermissionRequiredMixin, UpdateView):
    permission_required = "osquery.change_configuration"
    model = Configuration
    form_class = ConfigurationForm


class AddConfigurationPackView(PermissionRequiredMixin, CreateView):
    permission_required = "osquery.change_configuration"
    model = ConfigurationPack
    form_class = ConfigurationPackForm

    def dispatch(self, request, *args, **kwargs):
        self.configuration = get_object_or_404(Configuration, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["configuration"] = self.configuration
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.configuration
        return ctx


class UpdateConfigurationPackView(PermissionRequiredMixin, UpdateView):
    permission_required = "osquery.change_configuration"
    model = ConfigurationPack
    form_class = ConfigurationPackForm

    def get_object(self):
        return (
            self.model.objects.select_related("configuration")
                              .get(pk=self.kwargs["cp_pk"], configuration__pk=self.kwargs["pk"])
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["configuration"] = self.object.configuration
        return ctx


class RemoveConfigurationPackView(PermissionRequiredMixin, DeleteView):
    permission_required = "osquery.change_configuration"
    model = ConfigurationPack

    def get_object(self):
        configuration_pack = (self.model.objects
                                        .select_related("configuration", "pack")
                                        .get(pk=self.kwargs["cp_pk"], configuration__pk=self.kwargs["pk"]))
        self.configuration = configuration_pack.configuration
        return configuration_pack

    def get_success_url(self):
        return "{}#packs".format(self.configuration.get_absolute_url())
