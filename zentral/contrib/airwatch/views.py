import logging
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.views.generic import DetailView, ListView
from django.views.generic.edit import CreateView, FormView, UpdateView, DeleteView
from zentral.utils.osx_package import get_standalone_package_builders
from .api_client import APIClient, APIClientError
from .forms import AirwatchInstanceForm
from .models import AirwatchApp, AirwatchInstance


logger = logging.getLogger('zentral.contrib.airwatch.views')


# setup > airwatch instances


class AirwatchInstancesView(LoginRequiredMixin, ListView):
    model = AirwatchInstance

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        airwatch_instances_count = len(ctx["object_list"])
        if airwatch_instances_count == 0 or airwatch_instances_count > 1:
            suffix = "s"
        else:
            suffix = ""
        ctx["title"] = "{} Airwatch instance{}".format(airwatch_instances_count, suffix)
        return ctx


class CreateAirwatchInstanceView(LoginRequiredMixin, CreateView):
    model = AirwatchInstance
    form_class = AirwatchInstanceForm
    success_url = reverse_lazy("airwatch:airwatch_instances")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Create Airwatch instance"
        return ctx


class AirwatchInstanceView(LoginRequiredMixin, DetailView):
    model = AirwatchInstance
    form_class = AirwatchInstanceForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "{} Airwatch instance".format(self.object.user)
        ctx["apps"] = list(self.object.airwatchapp_set.all())
        ctx["app_number"] = len(ctx["apps"])
        create_airwatch_app_path = reverse("airwatch:create_airwatch_app", args=(self.object.id,))
        ctx["create_app_links"] = [("{}?builder={}".format(create_airwatch_app_path, k),
                                   v.name) for k, v in get_standalone_package_builders().items()]
        return ctx


class UpdateAirwatchInstanceView(LoginRequiredMixin, UpdateView):
    model = AirwatchInstance
    form_class = AirwatchInstanceForm
    success_url = reverse_lazy("airwatch:airwatch_instances")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Update Airwatch instance"
        return ctx


class DeleteAirwatchInstanceView(LoginRequiredMixin, DeleteView):
    model = AirwatchInstance
    success_url = reverse_lazy("airwatch:airwatch_instances")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Delete {}".format(self.object)
        return ctx

    def post(self, request, *args, **kwargs):
        airwatch_instance = get_object_or_404(AirwatchInstance, pk=kwargs["pk"])
        api_client = APIClient(airwatch_instance.host, airwatch_instance.port, airwatch_instance.path, airwatch_instance.user, airwatch_instance.password, airwatch_instance.aw_tenant_code)
        for app in airwatch_instance.airwatchapp_set.all():
            try:
                if api_client.delete_app(app.airwatch_id):
                    messages.info(request, "{} removed from Airwatch".format(app.name))
            except APIClientError:
                messages.warning(request, "Airwatch API Error. Could not cleanup apps.")
        return super().post(request, *args, **kwargs)


class CreateAirwatchAppView(LoginRequiredMixin, FormView):
    template_name = "airwatch/airwatchapp_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.airwatch_instance = get_object_or_404(AirwatchInstance, pk=kwargs["pk"])
        standalone_builders = get_standalone_package_builders()
        try:
            self.builder_key = request.GET["builder"]
            self.builder = standalone_builders[self.builder_key]
        except KeyError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_form_class(self):
        return self.builder.form

    def get_initial(self):
        return {"meta_business_unit": self.airwatch_instance.business_unit.meta_business_unit}

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["standalone"] = True
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["airwatch_instance"] = self.airwatch_instance
        ctx["title"] = "Create Airwatch app"
        ctx["builder_name"] = self.builder.name
        return ctx

    def form_valid(self, form):
        build_kwargs = form.get_build_kwargs()
        b = self.builder(self.airwatch_instance.business_unit,
                         **build_kwargs)
        package_filename, package_content = b.build()
        api_client = APIClient(self.airwatch_instance.host, self.airwatch_instance.port, self.airwatch_instance.path,
                               self.airwatch_instance.user, self.airwatch_instance.password, self.airwatch_instance.aw_tenant_code)
        try:
            response = api_client.upload_app(package_filename, package_content)
        except APIClientError:
            msg = "Could not upload app to airwatch"
            messages.warning(self.request, msg)
            logger.exception(msg)
        else:
            app = AirwatchApp(airwatch_instance=self.airwatch_instance,
                               name=response["attributes"]["name"],
                               airwatch_id=response["id"],
                               builder=self.builder_key,
                               build_kwargs=build_kwargs)
            app.save()
            messages.info(self.request, "{} uploaded to Airwatch".format(app.name))
        return HttpResponseRedirect(reverse("airwatch:airwatch_instance",
                                            args=(self.airwatch_instance.id,)))
