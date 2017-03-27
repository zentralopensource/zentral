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
from .forms import SimpleMDMInstanceForm
from .models import SimpleMDMApp, SimpleMDMInstance


logger = logging.getLogger('zentral.contrib.simplemdm.views')


# setup > simplemdm instances


class SimpleMDMInstancesView(LoginRequiredMixin, ListView):
    model = SimpleMDMInstance

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        simplemdm_instances_count = len(ctx["object_list"])
        if simplemdm_instances_count == 0 or simplemdm_instances_count > 1:
            suffix = "s"
        else:
            suffix = ""
        ctx["title"] = "{} SimpleMDM instance{}".format(simplemdm_instances_count, suffix)
        return ctx


class CreateSimpleMDMInstanceView(LoginRequiredMixin, CreateView):
    model = SimpleMDMInstance
    form_class = SimpleMDMInstanceForm
    success_url = reverse_lazy("simplemdm:simplemdm_instances")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Create SimpleMDM instance"
        return ctx


class SimpleMDMInstanceView(LoginRequiredMixin, DetailView):
    model = SimpleMDMInstance
    form_class = SimpleMDMInstanceForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "{} SimpleMDM instance".format(self.object.account_name)
        ctx["apps"] = list(self.object.simplemdmapp_set.all())
        ctx["app_number"] = len(ctx["apps"])
        create_simplemdm_app_path = reverse("simplemdm:create_simplemdm_app", args=(self.object.id,))
        ctx["create_app_links"] = [("{}?builder={}".format(create_simplemdm_app_path, k),
                                   v.name) for k, v in get_standalone_package_builders().items()]
        return ctx


class UpdateSimpleMDMInstanceView(LoginRequiredMixin, UpdateView):
    model = SimpleMDMInstance
    form_class = SimpleMDMInstanceForm
    success_url = reverse_lazy("simplemdm:simplemdm_instances")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Update SimpleMDM instance"
        return ctx


class DeleteSimpleMDMInstanceView(LoginRequiredMixin, DeleteView):
    model = SimpleMDMInstance
    success_url = reverse_lazy("simplemdm:simplemdm_instances")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Delete {}".format(self.object)
        return ctx

    def post(self, request, *args, **kwargs):
        simplemdm_instance = get_object_or_404(SimpleMDMInstance, pk=kwargs["pk"])
        api_client = APIClient(simplemdm_instance.api_key)
        for app in simplemdm_instance.simplemdmapp_set.all():
            try:
                if api_client.delete_app(app.simplemdm_id):
                    messages.info(request, "{} removed from SimpleMDM".format(app.name))
            except APIClientError:
                messages.warning(request, "SimpleMDM API Error. Could not cleanup apps.")
        return super().post(request, *args, **kwargs)


class CreateSimpleMDMAppView(LoginRequiredMixin, FormView):
    template_name = "simplemdm/simplemdmapp_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.simplemdm_instance = get_object_or_404(SimpleMDMInstance, pk=kwargs["pk"])
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
        return {"meta_business_unit": self.simplemdm_instance.business_unit.meta_business_unit}

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["standalone"] = True
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["simplemdm_instance"] = self.simplemdm_instance
        ctx["title"] = "Create SimpleMDM app"
        ctx["builder_name"] = self.builder.name
        return ctx

    def form_valid(self, form):
        build_kwargs = form.get_build_kwargs()
        b = self.builder(self.simplemdm_instance.business_unit,
                         **build_kwargs)
        package_filename, package_content = b.build()
        api_client = APIClient(self.simplemdm_instance.api_key)
        try:
            response = api_client.upload_app(package_filename, package_content)
        except APIClientError:
            msg = "Could not upload app to simplemdm"
            messages.warning(self.request, msg)
            logger.exception(msg)
        else:
            app = SimpleMDMApp(simplemdm_instance=self.simplemdm_instance,
                               name=response["attributes"]["name"],
                               simplemdm_id=response["id"],
                               builder=self.builder_key,
                               build_kwargs=build_kwargs)
            app.save()
            messages.info(self.request, "{} uploaded to SimpleMDM".format(app.name))
        return HttpResponseRedirect(reverse("simplemdm:simplemdm_instance",
                                            args=(self.simplemdm_instance.id,)))
