import logging
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView, TemplateView
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.utils.osx_package import get_standalone_package_builders
from .api_client import APIClient, APIClientError
from .forms import SimpleMDMInstanceForm
from .models import SimpleMDMApp, SimpleMDMInstance
from .utils import delete_app


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


class CreateSimpleMDMAppView(LoginRequiredMixin, TemplateView):
    template_name = "simplemdm/simplemdmapp_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.simplemdm_instance = get_object_or_404(SimpleMDMInstance, pk=kwargs["pk"])
        self.meta_business_unit = self.simplemdm_instance.business_unit.meta_business_unit
        standalone_builders = get_standalone_package_builders()
        try:
            self.builder_key = request.GET["builder"]
            self.builder = standalone_builders[self.builder_key]
        except KeyError:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_forms(self):
        secret_form_kwargs = {"prefix": "secret",
                              "no_restrictions": True,
                              "meta_business_unit": self.meta_business_unit}
        enrollment_form_kwargs = {"meta_business_unit": self.meta_business_unit,
                                  "standalone": True}  # w/o dependencies. all in the package.
        if self.request.method == "POST":
            secret_form_kwargs["data"] = self.request.POST
            enrollment_form_kwargs["data"] = self.request.POST
        return (EnrollmentSecretForm(**secret_form_kwargs),
                self.builder.form(**enrollment_form_kwargs))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["simplemdm_instance"] = self.simplemdm_instance
        ctx["title"] = "Create SimpleMDM app"
        ctx["builder_name"] = self.builder.name
        if "secret_form" not in kwargs or "enrollment_form" not in kwargs:
            ctx["secret_form"], ctx["enrollment_form"] = self.get_forms()
        return ctx

    def forms_invalid(self, secret_form, enrollment_form):
        return self.render_to_response(self.get_context_data(secret_form=secret_form,
                                                             enrollment_form=enrollment_form))

    def forms_valid(self, secret_form, enrollment_form):
        # make secret
        secret = secret_form.save()
        secret_form.save_m2m()
        # make enrollment
        enrollment = enrollment_form.save(commit=False)
        enrollment.version = 0
        enrollment.secret = secret
        enrollment.save()
        # SimpleMDM app
        app = SimpleMDMApp.objects.create(
            simplemdm_instance=self.simplemdm_instance,
            name="PENDING",  # temporary, no app uploaded yet
            simplemdm_id=0,  # temporary 0, no app uploaded yet
            builder=self.builder_key,
            enrollment_pk=enrollment.pk
        )
        # link from enrollment to app, for config update propagation
        enrollment.distributor = app
        enrollment.save()  # build package via callback call and set the simplemdm_id on the app after upload
        # info and return to SimpleMDM instance
        messages.info(self.request, "{} uploaded to SimpleMDM".format(app.name))
        return HttpResponseRedirect(app.get_absolute_url())

    def post(self, request, *args, **kwargs):
        secret_form, enrollment_form = self.get_forms()
        if secret_form.is_valid() and enrollment_form.is_valid():
            return self.forms_valid(secret_form, enrollment_form)
        else:
            return self.forms_invalid(secret_form, enrollment_form)


class DeleteSimpleMDMAppView(LoginRequiredMixin, DeleteView):
    model = SimpleMDMApp
    success_url = "/simplemdm/instances/{simplemdm_instance_id}/"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["title"] = "Delete {}".format(self.object)
        return ctx

    def post(self, request, *args, **kwargs):
        simplemdm_app = get_object_or_404(SimpleMDMApp, pk=kwargs["pk"], simplemdm_instance__pk=kwargs["instance_pk"])
        success_message, error_message = delete_app(simplemdm_app.simplemdm_instance.api_key,
                                                    simplemdm_app.simplemdm_id)
        if success_message:
            messages.info(request, success_message)
        if error_message:
            messages.warning(request, error_message)
        return super().post(request, *args, **kwargs)
